#ifndef BKCRACK_ATTACKAVX512_HPP
#define BKCRACK_ATTACKAVX512_HPP

#include <bkcrack/Attack.hpp>

// Internal worker selected only after checking CPU and OS support.
// Its constructor and Z traversal are compiled with the baseline ISA.
class AttackAvx512 final : public Attack
{
public:
    using Attack::Attack;

    void carryout(std::uint32_t z7_2_32);

private:
    friend class Attack;

    // Explore Y3 to Y7 with sixteen independent lanes.
    void exploreYlists(const ZPathContext& context);
};

#endif // BKCRACK_ATTACKAVX512_HPP
