#ifndef BKCRACK_CRC32TAB_HPP
#define BKCRACK_CRC32TAB_HPP

#include <bkcrack/types.hpp>

/// Lookup tables for CRC32 related computations
class Crc32Tab
{
public:
    /// \return CRC32 using a lookup table
    static auto crc32(std::uint32_t pval, std::uint8_t b) -> std::uint32_t
    {
        return pval >> 8 ^ instance.crctab[lsb(pval) ^ b];
    }

    /// \return CRC32^-1 using a lookup table
    static auto crc32inv(std::uint32_t crc, std::uint8_t b) -> std::uint32_t
    {
        return crc << 8 ^ instance.crcinvtab[msb(crc)] ^ b;
    }

    /// \brief Project X{i-4}[0,8) from the low bytes of four successive X states.
    /// \param plaintextBias Projection with all four low bytes zero for the same plaintext.
    static auto getXim4_0_8(std::uint8_t xim3, std::uint8_t xim2, std::uint8_t xim1, std::uint8_t xi,
                            std::uint8_t plaintextBias) -> std::uint8_t
    {
        return plaintextBias ^ instance.xinvlowtab[0][xim3] ^ instance.xinvlowtab[1][xim2] ^
               instance.xinvlowtab[2][xim1] ^ instance.xinvlowtab[3][xi];
    }

    /// \return Yi[24,32) from Zi and Z{i-1} using CRC32^-1
    static auto getYi_24_32(std::uint32_t zi, std::uint32_t zim1) -> std::uint32_t
    {
        return (crc32inv(zi, 0) ^ zim1) << 24;
    }

    /// \return Z{i-1}[10,32) from Zi[2,32) using CRC32^-1
    static auto getZim1_10_32(std::uint32_t zi_2_32) -> std::uint32_t
    {
        return crc32inv(zi_2_32, 0) & mask<10, 32>; // discard 10 least significant bits
    }

private:
    // initialize lookup tables
    Crc32Tab();

    // lookup tables
    std::array<std::uint32_t, 256> crctab;
    std::array<std::uint32_t, 256> crcinvtab;

    std::array<std::array<std::uint8_t, 256>, 4> xinvlowtab;

    static const Crc32Tab instance;
};

#endif // BKCRACK_CRC32TAB_HPP
