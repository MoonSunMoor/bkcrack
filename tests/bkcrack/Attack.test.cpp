#include <bkcrack/Attack.hpp>

#include <TestRunner.hpp>

#include <random>
#include <sstream>

namespace
{
const auto plaintext = std::vector<std::uint8_t>{
    'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!',
};
const auto ciphertext = std::vector<std::uint8_t>{
    0x3e, 0xb4, 0xc5, 0x92, 0x58, 0x40, 0x9a, 0x6c, 0xed, 0x99, 0x65, 0x81,
    0x66, 0x1b, 0x1d, 0xda, 0x5d, 0x8a, 0x8c, 0x30, 0x07, 0x76, 0x50, 0xbb,
};

const auto z7      = 0x74930e66;
const auto z7_2_32 = std::vector<std::uint32_t>{
    0x00000000, 0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000, 0x60000000, z7& mask<2, 32>,
    0x80000000, 0x90000000, 0xa0000000, 0xb0000000, 0xc0000000, 0xd0000000, 0xe0000000, 0xf0000000,
};

const auto z9      = 0x69196cee;
const auto z9_2_32 = std::vector<std::uint32_t>{
    0x00000000, 0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000, z9& mask<2, 32>, 0x70000000,
    0x80000000, 0x90000000, 0xa0000000, 0xb0000000, 0xc0000000, 0xd0000000, 0xe0000000,      0xf0000000,
};
} // namespace

TEST("simple case")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 0;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 8);
    CHECK(progress.done == 8);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("offset and extra plaintext")
{
    const auto plaintext2 = std::vector<std::uint8_t>{plaintext.begin() + 2, plaintext.end() - 2};
    const auto extra      = std::map<int, std::uint8_t>{{-2, 0x65 ^ 0x7d}, {-1, 0x81 ^ 0x0d}, {0, 'H'}, {11, '!'}};
    const auto data       = Data{ciphertext, {}, plaintext2, 2, extra};
    auto       start      = 0;
    auto       os         = std::ostringstream{};
    auto       progress   = Progress{os};

    const auto result = attack(data, z9_2_32, start, 7, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 7);
    CHECK(progress.done == 7);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("restart point before solution")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 4;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, false, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 8);
    CHECK(progress.done == 8);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::EarlyExit);
}

TEST("restart point past solution")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 8;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, false, progress);

    CHECK(result.empty());

    CHECK(start == 16);
    CHECK(progress.done == 16);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("exhaustive attack")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 0;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 1, true, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 16);
    CHECK(progress.done == 16);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("two-worker exhaustive attack")
{
    const auto data     = Data{ciphertext, {}, plaintext, 0, {}};
    auto       start    = 0;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z7_2_32, start, 7, 2, true, progress);

    CHECK(result.size() == 1);
    CHECK(result[0].getX() == 0xea9b4e4d);
    CHECK(result[0].getY() == 0xba789085);
    CHECK(result[0].getZ() == 0x5ff8707d);

    CHECK(start == 16);
    CHECK(progress.done == 16);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("reuse worker across completed Z paths")
{
    const auto data      = Data{ciphertext, {}, plaintext, 0, {}};
    auto       solutions = std::vector<Keys>{};
    auto       mutex     = std::mutex{};
    auto       os        = std::ostringstream{};
    auto       progress  = Progress{os};
    auto       worker    = Attack{data, 7, solutions, mutex, true, progress};

    worker.carryout(z7 & mask<2, 32>);
    CHECK(solutions.size() == 1);
    worker.carryout(0);
    CHECK(solutions.size() == 1);
    worker.carryout(z7 & mask<2, 32>);
    CHECK(solutions.size() == 2);
    for (const auto& keys : solutions)
    {
        CHECK(keys.getX() == 0xea9b4e4d);
        CHECK(keys.getY() == 0xba789085);
        CHECK(keys.getZ() == 0x5ff8707d);
    }
    CHECK(progress.state == Progress::State::Normal);
}

TEST("incorrect extra plaintext rejects a completed candidate")
{
    const auto plaintext2 = std::vector<std::uint8_t>{plaintext.begin() + 2, plaintext.end() - 2};
    const auto extra    = std::map<int, std::uint8_t>{{-2, (0x65 ^ 0x7d) ^ 1}, {-1, 0x81 ^ 0x0d}, {0, 'H'}, {11, '!'}};
    const auto data     = Data{ciphertext, {}, plaintext2, 2, extra};
    auto       start    = 0;
    auto       os       = std::ostringstream{};
    auto       progress = Progress{os};

    const auto result = attack(data, z9_2_32, start, 7, 2, true, progress);
    CHECK(result.empty());
    CHECK(start == 16);
    CHECK(progress.done == 16);
    CHECK(progress.total == 16);
    CHECK(progress.state == Progress::State::Normal);
}

TEST("generated inputs with short and shifted attack windows")
{
    for (const auto seed : {20261115u, 938421u})
        for (const auto length : {8u, 12u, 64u})
            for (const auto offset : {0, 3})
            {
                auto       rng = std::mt19937{seed};
                const auto initial =
                    std::array<std::uint32_t, 3>{static_cast<std::uint32_t>(rng()), static_cast<std::uint32_t>(rng()),
                                                 static_cast<std::uint32_t>(rng())};
                auto       keys       = Keys{initial[0], initial[1], initial[2]};
                const auto windowEnd  = length == 64 ? 19u : 7u;
                const auto plainStart = 12 + offset;
                auto       plain      = std::vector<std::uint8_t>(plainStart + length + 20);
                auto       cipher     = std::vector<std::uint8_t>(plain.size());
                auto       z          = std::uint32_t{};
                for (auto i = std::size_t{}; i < plain.size(); ++i)
                {
                    if (i == plainStart + windowEnd)
                        z = keys.getZ();
                    plain[i]  = static_cast<std::uint8_t>(rng());
                    cipher[i] = plain[i] ^ keys.getK();
                    keys.update(plain[i]);
                }
                auto extra = std::map<int, std::uint8_t>{};
                if (length == 8)
                    for (const auto i : {10, 12, 14, 16})
                        extra[offset + i] = plain[plainStart + i];
                const auto data       = Data{std::move(cipher),
                                             {},
                                             {plain.begin() + plainStart, plain.begin() + plainStart + length},
                                       offset,
                                       extra};
                const auto candidates = std::vector<std::uint32_t>{0, z & mask<2, 32>, 0x10000000, 0x20000000};
                for (const auto jobs : {1, 4})
                {
                    auto       start    = 0;
                    auto       os       = std::ostringstream{};
                    auto       progress = Progress{os};
                    const auto result   = attack(data, candidates, start, windowEnd, jobs, true, progress);
                    CHECK(result.size() == 1);
                    CHECK(result[0].getX() == initial[0]);
                    CHECK(result[0].getY() == initial[1]);
                    CHECK(result[0].getZ() == initial[2]);
                    CHECK(start == 4);
                    CHECK(progress.done == 4);
                    CHECK(progress.total == 4);
                    CHECK(progress.state == Progress::State::Normal);
                }
            }
}
