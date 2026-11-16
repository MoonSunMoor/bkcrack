#include "bkcrack/Attack.hpp"

#include <bkcrack/Crc32Tab.hpp>
#include <bkcrack/KeystreamTab.hpp>
#include <bkcrack/MultTab.hpp>
#include <bkcrack/log.hpp>

#include <algorithm>
#include <atomic>
#include <thread>

namespace
{
constexpr auto forwardRange     = 1u << 24;
constexpr auto forwardCellWidth = 1u << 27;
constexpr auto forwardGridStep  = 32 * MultTab::mult;

static_assert(32ull * MultTab::mult == (1ull << 32) + forwardGridStep);
static_assert(255ull * (MultTab::mult - forwardCellWidth) + forwardRange - 1 < 2ull * forwardCellWidth);
static_assert(forwardCellWidth - 31 * (MultTab::mult - forwardCellWidth) > 6 * forwardGridStep);
static_assert(forwardCellWidth < 8 * forwardGridStep);

struct ForwardFiber
{
    std::uint32_t first, second;
    std::uint32_t residualFirst, residualSecond;
    bool          keepFirst, keepSecond;
};

// Find the bytes u satisfying uint32(difference - mult * u) < 2^24.
auto getForwardFiber(std::uint32_t difference) -> ForwardFiber
{
    const auto cell          = difference >> 27;
    const auto offset        = difference - MultTab::mult * cell;
    const auto quotient      = offset / forwardGridStep;
    const auto first         = cell + (quotient << 5);
    const auto residualFirst = offset - quotient * forwardGridStep;

    // Only the neighboring residue, with quotient 6 or 7, can yield another byte.
    const auto secondOffset   = offset + MultTab::mult - (cell == 0 ? forwardGridStep : 0u);
    const auto secondQuotient = 6u + std::uint32_t{secondOffset >= 7 * forwardGridStep};
    const auto second         = ((cell - 1) & 31) + (secondQuotient << 5);
    const auto residualSecond = secondOffset - secondQuotient * forwardGridStep;
    return {first,
            second,
            residualFirst,
            residualSecond,
            offset < forwardCellWidth && residualFirst < forwardRange,
            residualSecond < forwardRange};
}

auto getX3PlaintextBias(const Data& data, std::size_t index) -> std::uint8_t
{
    auto x = std::uint32_t{};
    for (auto i = 4; i <= 6; ++i)
        x = Crc32Tab::crc32(x, data.plaintext[index + i]) & mask<8, 32>;
    for (auto i = 6; i >= 3; --i)
        x = Crc32Tab::crc32inv(x, data.plaintext[index + i]);
    return lsb(x);
}
} // namespace

Attack::Attack(const Data& data, std::size_t index, std::vector<Keys>& solutions, std::mutex& solutionsMutex,
               bool exhaustive, Progress& progress)
: data{data}
, index{index + 1 - Attack::contiguousSize}
, x3PlaintextBias{getX3PlaintextBias(data, this->index)}
, solutions{solutions}
, solutionsMutex{solutionsMutex}
, exhaustive{exhaustive}
, progress{progress}
{
}

void Attack::carryout(std::uint32_t z7_2_32)
{
    zlist[7] = z7_2_32;
    exploreZlists(7);
}

void Attack::exploreZlists(int i)
{
    if (i != 0) // the Z-list is not complete so generate Z{i-1}[2,32) values
    {
        // get Z{i-1}[10,32) from CRC32^-1
        const auto zim1_10_32 = Crc32Tab::getZim1_10_32(zlist[i]);

        // get Z{i-1}[2,16) values from keystream byte k{i-1} and Z{i-1}[10,16)
        for (const auto zim1_2_16 : KeystreamTab::getZi_2_16_vector(data.keystream[index + i - 1], zim1_10_32))
        {
            // add Z{i-1}[2,32) to the Z-list
            zlist[i - 1] = zim1_10_32 | zim1_2_16;

            // find Zi[0,2) from CRC32^1
            zlist[i] &= mask<2, 32>; // discard 2 least significant bits
            zlist[i] |= (Crc32Tab::crc32inv(zlist[i], 0) ^ zlist[i - 1]) >> 8;

            // get Y{i+1}[24,32)
            if (i < 7)
                ylist[i + 1] = Crc32Tab::getYi_24_32(zlist[i + 1], zlist[i]);

            exploreZlists(i - 1);
        }
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        // This constraint is shared by every Y candidate for the completed Z-list.
        y1Constraint = Crc32Tab::getYi_24_32(zlist[1], zlist[0]) & mask<26, 32>;

        // Guess Y3[8,24) and use the Y2 bound to enumerate exact Y3 low bytes.
        const auto y3High = ylist[3] & mask<24, 32>;
        const auto bound  = maxdiff<24> + (ylist[2] & mask<24, 32>);
        for (auto middle = std::uint32_t{}, prod = MultTab::multInv * y3High - MultTab::multInv; middle < 1u << 24;
             middle += 1u << 8, prod += MultTab::multInv << 8)
        {
            const auto& fiber = MultTab::getExactProdFiber(bound - prod);
            for (const auto low : fiber)
            {
                ylist[3] = y3High | middle | low;
                exploreYlists(3);
            }
        }
    }
}

void Attack::exploreYlists(int i)
{
    if (i != 7)
    {
        const auto base  = MultTab::mult * ylist[i] + 1;
        const auto upper = (ylist[i + 1] & mask<24, 32>)+(forwardRange - 1);
        const auto fiber = getForwardFiber(upper - base);
        if (fiber.keepFirst)
        {
            xlist[i + 1] = fiber.first;
            ylist[i + 1] = upper - fiber.residualFirst;
            exploreYlists(i + 1);
        }
        if (fiber.keepSecond)
        {
            xlist[i + 1] = fiber.second;
            ylist[i + 1] = upper - fiber.residualSecond;
            exploreYlists(i + 1);
        }
    }
    else
        testXlist();
}

void Attack::testXlist()
{
    // Reject candidates using only low X3 before reconstructing the full X states.
    const auto x3_0_8 =
        Crc32Tab::getXim4_0_8(lsb(xlist[4]), lsb(xlist[5]), lsb(xlist[6]), lsb(xlist[7]), x3PlaintextBias);
    if (((ylist[3] - 1) * MultTab::multInv - x3_0_8 - 1) * MultTab::multInv - y1Constraint > maxdiff<26>)
        return;

    verifyXlist();
}

void Attack::verifyXlist()
{
    // compute X7
    for (auto i = 5; i <= 7; i++)
        xlist[i] = (Crc32Tab::crc32(xlist[i - 1], data.plaintext[index + i - 1]) & mask<8, 32>) // discard the LSB
                   | lsb(xlist[i]);                                                             // set the LSB

    // compute X3
    auto x = xlist[7];
    for (auto i = 6; i >= 3; i--)
        x = Crc32Tab::crc32inv(x, data.plaintext[index + i]);

    // decipher and filter by comparing with remaining contiguous plaintext forward
    auto keysForward = Keys{xlist[7], ylist[7], zlist[7]};
    keysForward.update(data.plaintext[index + 7]);
    for (auto p = data.plaintext.begin() + index + 8, c = data.ciphertext.begin() + data.offset + index + 8;
         p != data.plaintext.end(); ++p, ++c)
    {
        if ((*c ^ keysForward.getK()) != *p)
            return;
        keysForward.update(*p);
    }

    auto indexForward = data.offset + data.plaintext.size();

    // and also backward
    auto keysBackward = Keys{x, ylist[3], zlist[3]};
    for (auto p = std::reverse_iterator{data.plaintext.begin() + index + 3},
              c = std::reverse_iterator{data.ciphertext.begin() + data.offset + index + 3};
         p != data.plaintext.rend(); ++p, ++c)
    {
        keysBackward.updateBackward(*c);
        if ((*c ^ keysBackward.getK()) != *p)
            return;
    }

    auto indexBackward = data.offset;

    // continue filtering with extra known plaintext
    for (const auto& [extraIndex, extraByte] : data.extraPlaintext)
    {
        auto p = std::uint8_t{};
        if (extraIndex < indexBackward)
        {
            keysBackward.updateBackward(data.ciphertext, indexBackward, extraIndex);
            indexBackward = extraIndex;
            p             = data.ciphertext[indexBackward] ^ keysBackward.getK();
        }
        else
        {
            keysForward.update(data.ciphertext, indexForward, extraIndex);
            indexForward = extraIndex;
            p            = data.ciphertext[indexForward] ^ keysForward.getK();
        }

        if (p != extraByte)
            return;
    }

    // all tests passed so the keys are found

    // get the keys associated with the initial state
    keysBackward.updateBackward(data.ciphertext, indexBackward, 0);

    {
        const auto lock = std::scoped_lock{solutionsMutex};
        solutions.push_back(keysBackward);
    }

    progress.log([&keysBackward](std::ostream& os) { os << "Keys: " << keysBackward << std::endl; });

    if (!exhaustive)
        progress.state = Progress::State::EarlyExit;
}

auto attack(const Data& data, const std::vector<std::uint32_t>& zi_2_32_vector, int& start, std::size_t index, int jobs,
            const bool exhaustive, Progress& progress) -> std::vector<Keys>
{
    const auto* candidates = zi_2_32_vector.data();
    const auto  size       = static_cast<int>(zi_2_32_vector.size());

    auto solutions      = std::vector<Keys>{};
    auto solutionsMutex = std::mutex{};
    auto worker         = Attack{data, index, solutions, solutionsMutex, exhaustive, progress};

    progress.done  = start;
    progress.total = size;

    const auto threadCount        = std::clamp(jobs, 1, size);
    auto       threads            = std::vector<std::thread>{};
    auto       nextCandidateIndex = std::atomic<int>{start};
    for (auto i = 0; i < threadCount; ++i)
        threads.emplace_back(
            [&nextCandidateIndex, size, &progress, candidates, worker]() mutable
            {
                for (auto i = nextCandidateIndex++; i < size; i = nextCandidateIndex++)
                {
                    worker.carryout(candidates[i]);
                    progress.done++;

                    if (progress.state != Progress::State::Normal)
                        break;
                }
            });
    for (auto& thread : threads)
        thread.join();

    start = std::min(nextCandidateIndex.load(), size);

    return solutions;
}
