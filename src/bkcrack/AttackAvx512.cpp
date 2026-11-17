#include "AttackAvx512.hpp"

void AttackAvx512::carryout(std::uint32_t z7_2_32)
{
    zlist[7] = z7_2_32;
    exploreZlists<AttackAvx512>(7);
}

void AttackAvx512::exploreYlists()
{
    const auto context = makeYContext();
    exploreYlists(context);
}

auto AttackAvx512::makeYContext() const -> Avx512YContext
{
    auto context            = Avx512YContext{};
    context.y1Constraint    = y1Constraint;
    context.x3PlaintextBias = x3PlaintextBias;
    for (auto i = std::size_t{}; i < context.yHigh.size(); ++i)
        context.yHigh[i] = ylist[i + 2] & mask<24, 32>;
    return context;
}

void AttackAvx512::verifyXlist(const Avx512Candidate& candidate)
{
    // The SIMD search keeps its state in local vectors and its fixed context.
    // Only accepted candidates enter the existing verification state.
    ylist[3] = candidate.y3;
    ylist[7] = candidate.y7;
    for (auto i = 4; i <= 7; ++i)
        xlist[i] = (candidate.packedX >> (8 * (i - 4))) & mask<0, 8>;
    Attack::verifyXlist();
}
