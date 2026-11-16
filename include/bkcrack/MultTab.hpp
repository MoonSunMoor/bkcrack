#ifndef BKCRACK_MULTTAB_HPP
#define BKCRACK_MULTTAB_HPP

#include <bkcrack/types.hpp>

/// Lookup tables and arithmetic fibers for multiplication related computations
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

    /// Two forward byte candidates and their modular residuals.
    /// Only fields whose corresponding keep flag is true describe a valid candidate.
    struct ForwardFiber
    {
        std::uint32_t first, second;
        std::uint32_t residualFirst, residualSecond;
        bool          keepFirst, keepSecond;
    };

    /// \return an immutable range of bytes x such that
    /// difference - x*multInv <= maxdiff<24>, modulo 2^32.
    static auto getExactProdFiber(std::uint32_t difference) -> const ProdFiber&
    {
        const auto& bucket = instance.exactprodfiber[msb(difference)];
        const auto  low    = difference & mask<0, 24>;
        const auto  index  = (low >= bucket.cuts[0]) + (low >= bucket.cuts[1]) + (low >= bucket.cuts[2]);
        return bucket.values[index];
    }

    /// Return byte candidates u satisfying uint32(difference - mult*u) < 2^24.
    /// Each valid residual equals difference - mult*u and can be reused to restore Y.
    /// Candidate order is unspecified.
    static auto getForwardFiber(std::uint32_t difference) -> ForwardFiber
    {
        const auto cell          = difference >> 27;
        const auto offset        = difference - mult * cell;
        const auto quotient      = offset / forwardGridStep;
        const auto first         = cell + (quotient << 5);
        const auto residualFirst = offset - quotient * forwardGridStep;

        // Only the neighboring residue, with quotient 6 or 7, can yield another byte.
        const auto secondOffset   = offset + mult - (cell == 0 ? forwardGridStep : 0u);
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

    /// Multiplicative constant used in traditional PKWARE encryption
    static constexpr std::uint32_t mult = 0x08088405;

    /// Multiplicative inverse of mult modulo 2^32
    static constexpr std::uint32_t multInv = 0xd94fa8cd;
    static_assert(mult * multInv == 1);

private:
    static constexpr auto forwardRange     = 1u << 24;
    static constexpr auto forwardCellWidth = 1u << 27;
    static constexpr auto forwardGridStep  = 32 * mult;

    static_assert(32ull * mult == (1ull << 32) + forwardGridStep);
    static_assert(255ull * (mult - forwardCellWidth) + forwardRange - 1 < 2ull * forwardCellWidth);
    static_assert(forwardCellWidth - 31 * (mult - forwardCellWidth) > 6 * forwardGridStep);
    static_assert(forwardCellWidth < 8 * forwardGridStep);

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
