#include "bkcrack/Attack.hpp"

#include <bkcrack/Crc32Tab.hpp>
#include <bkcrack/MultTab.hpp>

void Attack::exploreYlists(const ZPathContext& context)
{
    // guess Y7[8,24) and keep prod == (Y7[8,32) - 1) * mult^-1
    for (auto y7_8_24 = std::uint32_t{}, prod = (MultTab::multInv * msb(context.yHigh[5]) << 24) - MultTab::multInv;
         y7_8_24 < 1 << 24; y7_8_24 += 1 << 8, prod += MultTab::multInv << 8)
    {
        // Reflect the Y6 bound to get exactly the possible Y7[0,8) values.
        const auto& fiber = MultTab::getExactProdFiber(maxdiff<24> + context.yHigh[4] - prod);
        for (const auto y7_0_8 : fiber)
        {
            ylist[7] = y7_0_8 | y7_8_24 | context.yHigh[5];
            exploreYlists(7, context);
        }
    }
}

void Attack::exploreYlists(int i, const ZPathContext& context)
{
    if (i != 3) // the Y-list is not complete so generate Y{i-1} values
    {
        const auto fy  = (ylist[i] - 1) * MultTab::multInv;
        const auto ffy = (fy - 1) * MultTab::multInv;

        // get exactly the possible LSB(Xi) values satisfying the Y{i-2} bound
        const auto& fiber = MultTab::getExactProdFiber(ffy - context.yHigh[i - 4]);
        for (const auto xi_0_8 : fiber)
        {
            // compute corresponding Y{i-1}
            const auto yim1 = fy - xi_0_8;

            // filter values with Y{i-1}[24,32)
            if (msb(yim1) == msb(context.yHigh[i - 3]))
            {
                ylist[i - 1] = yim1;
                xlist[i]     = xi_0_8;
                exploreYlists(i - 1, context);
            }
        }
    }
    else // the Y-list is complete so check if the corresponding X-list is valid
        testXlist(context);
}

void Attack::testXlist(const ZPathContext& context)
{
    // Reject candidates using only low X3 before reconstructing the full X states.
    const auto x3_0_8 =
        Crc32Tab::getXim4_0_8(lsb(xlist[4]), lsb(xlist[5]), lsb(xlist[6]), lsb(xlist[7]), context.x3PlaintextBias);
    if (((ylist[3] - 1) * MultTab::multInv - x3_0_8 - 1) * MultTab::multInv - context.y1Constraint > maxdiff<26>)
        return;

    const auto packedX = std::uint32_t{lsb(xlist[4])} | (std::uint32_t{lsb(xlist[5])} << 8) |
                         (std::uint32_t{lsb(xlist[6])} << 16) | (std::uint32_t{lsb(xlist[7])} << 24);
    verifyXlist(context, AttackCandidate{ylist[3], ylist[7], packedX});
}
