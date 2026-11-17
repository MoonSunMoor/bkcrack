#include "bkcrack/Attack.hpp"

#include <bkcrack/Crc32Tab.hpp>
#include <bkcrack/MultTab.hpp>

void Attack::exploreYlists()
{
    // Guess Y3[8,24) and use the Y2 bound to enumerate exact Y3 low bytes.
    const auto y3High = ylist[3] & mask<24, 32>;
    const auto bound  = maxdiff<24> + (ylist[2] & mask<24, 32>);
    for (auto middle = std::uint32_t{}, prod = MultTab::multInv * y3High - MultTab::multInv; middle < 1u << 24;
         middle += 1u << 8, prod += MultTab::multInv << 8)
    {
        const auto& fiber = MultTab::getExactProdFiber(bound - prod);
        for (const auto low : fiber)
        {
            ylist[3] = y3High | middle | low;
            exploreYlists(3);
        }
    }
}

void Attack::exploreYlists(int i)
{
    if (i != 7)
    {
        const auto base  = MultTab::mult * ylist[i] + 1;
        const auto upper = (ylist[i + 1] & mask<24, 32>)+mask<0, 24>;
        const auto fiber = MultTab::getForwardFiber(upper - base);
        if (fiber.keepFirst)
        {
            xlist[i + 1] = fiber.first;
            ylist[i + 1] = upper - fiber.residualFirst;
            exploreYlists(i + 1);
        }
        if (fiber.keepSecond)
        {
            xlist[i + 1] = fiber.second;
            ylist[i + 1] = upper - fiber.residualSecond;
            exploreYlists(i + 1);
        }
    }
    else
        testXlist();
}

void Attack::testXlist()
{
    // Reject candidates using only low X3 before reconstructing the full X states.
    const auto x3_0_8 =
        Crc32Tab::getXim4_0_8(lsb(xlist[4]), lsb(xlist[5]), lsb(xlist[6]), lsb(xlist[7]), x3PlaintextBias);
    if (((ylist[3] - 1) * MultTab::multInv - x3_0_8 - 1) * MultTab::multInv - y1Constraint > maxdiff<26>)
        return;

    verifyXlist();
}
