#include <bkcrack/Crc32Tab.hpp>

#include <TestRunner.hpp>

#include <random>
#include <string_view>

TEST("crc32")
{
    CHECK(Crc32Tab::crc32(0x00000000, 0x00) == 0x00000000);
    CHECK(Crc32Tab::crc32(0x12345678, 0x00) == 0x5ecccd58);
    CHECK(Crc32Tab::crc32(0x12345678, 0x42) == 0xc61eede4);
    CHECK(Crc32Tab::crc32(0x12345678, 0xff) == 0x73ce22d5);
    CHECK(Crc32Tab::crc32(0xffffffff, 0xff) == 0x00ffffff);
}

TEST("crc32inv")
{
    CHECK(Crc32Tab::crc32inv(0x00000000, 0x00) == 0x00000000);
    CHECK(Crc32Tab::crc32inv(0x5ecccd58, 0x00) == 0x12345678);
    CHECK(Crc32Tab::crc32inv(0xc61eede4, 0x42) == 0x12345678);
    CHECK(Crc32Tab::crc32inv(0x73ce22d5, 0xff) == 0x12345678);
    CHECK(Crc32Tab::crc32inv(0x00ffffff, 0xff) == 0xffffffff);
}

TEST("getYi_24_32")
{
    CHECK(Crc32Tab::getYi_24_32(0x00000000, 0x00000000) == 0x00000000);
    CHECK(Crc32Tab::getYi_24_32(0x5ecccd58, 0x12345678) == 0x00000000);
    CHECK(Crc32Tab::getYi_24_32(0xc61eede4, 0x12345678) == 0x42000000);
    CHECK(Crc32Tab::getYi_24_32(0x73ce22d5, 0x12345678) == 0xff000000);
    CHECK(Crc32Tab::getYi_24_32(0x00ffffff, 0xffffffff) == 0xff000000);
}

TEST("getZim1_10_32")
{
    CHECK(Crc32Tab::getZim1_10_32(0x00000000) == 0x00000000);
    CHECK(Crc32Tab::getZim1_10_32(0x5ecccd58) == 0x12345400);
    CHECK(Crc32Tab::getZim1_10_32(0xc61eede4) == 0x12345400);
    CHECK(Crc32Tab::getZim1_10_32(0x73ce22d5) == 0x12345400);
    CHECK(Crc32Tab::getZim1_10_32(0x00ffffff) == 0xfffffc00);
}

TEST("compute message CRC-32")
{
    const auto message = std::string_view{"Hello World!"};

    auto crc = 0xffffffff;
    for (const auto byte : message)
        crc = Crc32Tab::crc32(crc, byte);
    crc ^= 0xffffffff;

    CHECK(crc == 0x1c291ca3);
}

namespace
{
auto referenceCrc32(std::uint32_t x, std::uint8_t plaintext) -> std::uint32_t
{
    x ^= plaintext;
    for (auto i = 0; i < 8; ++i)
        x = (x >> 1) ^ ((x & 1) ? 0xedb88320u : 0u);
    return x;
}

auto referenceCrc32inv(std::uint32_t x, std::uint8_t plaintext) -> std::uint32_t
{
    for (auto i = 0; i < 8; ++i)
    {
        const auto bit = x >> 31;
        x              = ((x ^ (bit ? 0xedb88320u : 0u)) << 1) | bit;
    }
    return x ^ plaintext;
}

auto referenceX3(const std::array<std::uint8_t, 4>& low, const std::array<std::uint8_t, 4>& plaintext) -> std::uint32_t
{
    auto x = std::uint32_t{low[0]};
    for (auto i = 1; i < 4; ++i)
        x = (referenceCrc32(x, plaintext[i]) & 0xffffff00u) | low[i];
    for (auto i = 3; i >= 0; --i)
        x = referenceCrc32inv(x, plaintext[i]);
    return x;
}
} // namespace

TEST("low X projection basis")
{
    const auto zero = std::array<std::uint8_t, 4>{};
    for (auto byte = std::size_t{}; byte < 4; ++byte)
        for (auto value = 0u; value < 256; ++value)
        {
            auto low  = zero;
            low[byte] = value;
            CHECK(Crc32Tab::getXim4_0_8(low[0], low[1], low[2], low[3], 0) == lsb(referenceX3(low, zero)));
        }
}

TEST("low X projection with plaintext bias")
{
    const auto zero   = std::array<std::uint8_t, 4>{};
    auto       random = std::mt19937{20261115};
    for (auto i = 0; i < 100000; ++i)
    {
        auto low       = zero;
        auto plaintext = zero;
        for (auto byte = std::size_t{}; byte < 4; ++byte)
        {
            low[byte]       = static_cast<std::uint8_t>(random());
            plaintext[byte] = static_cast<std::uint8_t>(random());
        }
        const auto bias = lsb(referenceX3(zero, plaintext));
        CHECK(Crc32Tab::getXim4_0_8(low[0], low[1], low[2], low[3], bias) == lsb(referenceX3(low, plaintext)));
    }
}
