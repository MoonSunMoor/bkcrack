#ifndef BKCRACK_ATTACKAVX512_HPP
#define BKCRACK_ATTACKAVX512_HPP

#include <bkcrack/Attack.hpp>

// Fixed Y constraints for one synchronous AVX512 search.
struct Avx512YContext
{
    std::array<std::uint32_t, 6> yHigh{}; // Y2..Y7 high bytes in their original positions
    std::uint32_t                y1Constraint{};
    std::uint8_t                 x3PlaintextBias{};
};

struct Avx512Candidate
{
    std::uint32_t y3{};
    std::uint32_t y7{};
    std::uint32_t packedX{}; // low bytes of X4..X7, least significant first
};

// Internal worker selected only after checking CPU and OS support.
// Its constructor and Z traversal are compiled with the baseline ISA.
class AttackAvx512 final : public Attack
{
public:
    using Attack::Attack;

    void carryout(std::uint32_t z7_2_32);

private:
    friend class Attack;

    void exploreYlists();
    auto makeYContext() const -> Avx512YContext;
    void verifyXlist(const Avx512Candidate& candidate);

    // Explore Y3 to Y7 with sixteen independent lanes.
    void exploreYlists(const Avx512YContext& context);
};

// Defined in Attack.cpp with the baseline ISA options.
extern template void Attack::exploreZlists<AttackAvx512>(int);

#endif // BKCRACK_ATTACKAVX512_HPP
