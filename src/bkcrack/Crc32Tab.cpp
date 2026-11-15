#include "bkcrack/Crc32Tab.hpp"

const Crc32Tab Crc32Tab::instance;

Crc32Tab::Crc32Tab()
{
    // CRC32 polynomial representation
    constexpr auto crcPolynom = 0xedb88320;

    for (auto b = 0; b < 256; b++)
    {
        auto crc = static_cast<std::uint32_t>(b);
        // compute CRC32 from the original definition
        for (auto i = 0; i < 8; i++)
            if (crc & 1)
                crc = crc >> 1 ^ crcPolynom;
            else
                crc = crc >> 1;

        // fill lookup tables
        crctab[b]           = crc;
        crcinvtab[msb(crc)] = crc << 8 ^ b;
    }

    // Build the linear projection after both CRC tables are initialized.
    // Each table represents one low X byte with zero plaintext and zero other bytes.
    for (auto byte = std::size_t{}; byte < xinvlowtab.size(); ++byte)
        for (auto value = 0u; value < 256; ++value)
        {
            auto low  = std::array<std::uint8_t, 4>{};
            low[byte] = value;
            auto x    = std::uint32_t{low[0]};
            for (auto i = 1; i < 4; ++i)
                x = (crc32(x, 0) & mask<8, 32>) | low[i];
            for (auto i = 0; i < 4; ++i)
                x = crc32inv(x, 0);
            xinvlowtab[byte][value] = lsb(x);
        }
}
