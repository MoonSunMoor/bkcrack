#ifndef BKCRACK_MULTTAB_HPP
#define BKCRACK_MULTTAB_HPP

#include <bkcrack/types.hpp>

/// Lookup tables for multiplication related computations
class MultTab
{
public:
    /// Up to two multiplication fiber candidates, in ascending order
    struct alignas(4) ProdFiber
    {
        std::array<std::uint8_t, 2> values{};
        std::uint8_t                count{};

        auto begin() const -> const std::uint8_t*
        {
            return values.data();
        }

        auto end() const -> const std::uint8_t*
        {
            return values.data() + count;
        }
    };

    static_assert(sizeof(ProdFiber) == 4);

    /// \return an immutable range of bytes x such that
    /// difference - x*multInv <= maxdiff<24>, modulo 2^32.
    static auto getExactProdFiber(std::uint32_t difference) -> const ProdFiber&
    {
        const auto& bucket = instance.exactprodfiber[msb(difference)];
        const auto  low    = difference & mask<0, 24>;
        const auto  index  = (low >= bucket.cuts[0]) + (low >= bucket.cuts[1]) + (low >= bucket.cuts[2]);
        return bucket.values[index];
    }

    /// Multiplicative constant used in traditional PKWARE encryption
    static constexpr std::uint32_t mult = 0x08088405;

    /// Multiplicative inverse of mult modulo 2^32
    static constexpr std::uint32_t multInv = 0xd94fa8cd;
    static_assert(mult * multInv == 1);

private:
    // initialize lookup tables
    MultTab();

    // Each high-byte bucket has at most three low-24-bit boundaries and four exact fibers.
    struct alignas(32) ExactProdFiber
    {
        std::array<std::uint32_t, 3> cuts{1u << 24, 1u << 24, 1u << 24};
        std::array<ProdFiber, 4>     values{};
    };
    static_assert(sizeof(ExactProdFiber) == 32);

    // lookup tables
    std::array<ExactProdFiber, 256> exactprodfiber;

    static const MultTab instance;
};

#endif // BKCRACK_MULTTAB_HPP
