#include "bkcrack/Attack.hpp"

#include <bkcrack/Crc32Tab.hpp>
#include <bkcrack/KeystreamTab.hpp>
#include <bkcrack/log.hpp>

#ifdef BKCRACK_HAS_AVX512
#include "AttackAvx512.hpp"
#endif

namespace
{
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
    exploreZlists<Attack>(7);
}

#ifdef BKCRACK_HAS_AVX512
void AttackAvx512::carryout(std::uint32_t z7_2_32)
{
    zlist[7] = z7_2_32;
    exploreZlists<AttackAvx512>(7);
}
#endif

template <class Worker>
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

            exploreZlists<Worker>(i - 1);
        }
    }
    else // the Z-list is complete so iterate over possible Y values
    {
        const auto context = makeZPathContext();
        static_cast<Worker&>(*this).exploreYlists(context);
    }
}

auto Attack::makeZPathContext() const -> ZPathContext
{
    auto context            = ZPathContext{};
    context.index           = index;
    context.z               = zlist;
    context.y1Constraint    = Crc32Tab::getYi_24_32(zlist[1], zlist[0]) & mask<26, 32>;
    context.x3PlaintextBias = x3PlaintextBias;
    // Y0/Y1 are not search constraints; copy only the initialized Y2..Y7 high bytes.
    for (auto i = std::size_t{}; i < context.yHigh.size(); ++i)
        context.yHigh[i] = ylist[i + 2] & mask<24, 32>;
    if (index + contiguousSize < data.keystream.size())
        context.nextKeystream = data.keystream[index + contiguousSize];
    return context;
}

void Attack::verifyXlist(const ZPathContext& context, const AttackCandidate& candidate)
{
    const auto index = context.index;

    // Reconstruct X7 locally; verification must not modify the producer's search state.
    auto x7 = std::uint32_t{lsb(candidate.packedX)};
    for (auto i = 5; i <= 7; ++i)
        x7 = (Crc32Tab::crc32(x7, data.plaintext[index + i - 1]) & mask<8, 32>) |
             ((candidate.packedX >> (8 * (i - 4))) & mask<0, 8>);

    // compute X3
    auto x = x7;
    for (auto i = 6; i >= 3; i--)
        x = Crc32Tab::crc32inv(x, data.plaintext[index + i]);

    // decipher and filter by comparing with remaining contiguous plaintext forward
    auto keysForward = Keys{x7, candidate.y7, context.z[7]};
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
    auto keysBackward = Keys{x, candidate.y3, context.z[3]};
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
