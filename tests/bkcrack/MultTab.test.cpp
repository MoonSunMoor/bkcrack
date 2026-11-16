#include <bkcrack/MultTab.hpp>

#include <TestRunner.hpp>

#include <algorithm>
#include <limits>
#include <random>

namespace
{
auto exactProdFiber(std::uint32_t difference) -> std::vector<std::uint8_t>
{
    const auto& fiber = MultTab::getExactProdFiber(difference);
    CHECK(fiber.count <= fiber.values.size());

    const auto result = std::vector<std::uint8_t>{fiber.begin(), fiber.end()};
    CHECK(std::ranges::is_sorted(result));
    CHECK(std::adjacent_find(result.begin(), result.end()) == result.end());
    return result;
}

auto referenceProdFiber(std::uint32_t difference) -> std::vector<std::uint8_t>
{
    auto result = std::vector<std::uint8_t>{};
    for (auto x = std::uint32_t{}; x < 256; ++x)
        if (difference - x * MultTab::multInv <= maxdiff<24>)
            result.push_back(x);
    return result;
}
auto forwardFiber(std::uint32_t difference) -> std::vector<std::uint32_t>
{
    const auto fiber  = MultTab::getForwardFiber(difference);
    auto       result = std::vector<std::uint32_t>{};
    const auto append = [&](std::uint32_t value, std::uint32_t residual)
    {
        CHECK(value < 256);
        CHECK(residual < (1u << 24));
        CHECK(residual == difference - MultTab::mult * value);
        result.push_back(value);
    };
    if (fiber.keepFirst)
        append(fiber.first, fiber.residualFirst);
    if (fiber.keepSecond)
        append(fiber.second, fiber.residualSecond);
    std::ranges::sort(result);
    CHECK(std::adjacent_find(result.begin(), result.end()) == result.end());
    return result;
}

auto referenceForwardFiber(std::uint32_t difference) -> std::vector<std::uint32_t>
{
    auto result = std::vector<std::uint32_t>{};
    for (auto value = std::uint32_t{}; value < 256; ++value)
        if (difference - value * MultTab::mult < (1u << 24))
            result.push_back(value);
    return result;
}
} // namespace

TEST("exact multiplication fibers across every constant interval")
{
    // Membership changes only at the endpoints of the 256 modular intervals.
    // Include bucket boundaries to also check the lookup's high-byte partition.
    auto points = std::vector<std::uint64_t>{0, std::uint64_t{1} << 32};
    for (auto x = std::uint32_t{}; x < 256; ++x)
    {
        points.push_back(x * MultTab::multInv);
        points.push_back(std::uint32_t{x * MultTab::multInv + maxdiff<24> + 1});
        points.push_back(x << 24);
    }
    std::ranges::sort(points);
    points.erase(std::unique(points.begin(), points.end()), points.end());

    auto counts = std::array<bool, 3>{};
    for (auto i = std::size_t{}; i + 1 < points.size(); ++i)
    {
        const auto begin    = points[i];
        const auto end      = points[i + 1] - 1;
        const auto expected = referenceProdFiber(begin);
        CHECK(expected.size() <= 2);
        counts[expected.size()] = true;
        for (const auto point : {begin, begin + (end - begin) / 2, end})
        {
            CHECK(referenceProdFiber(point) == expected);
            CHECK(exactProdFiber(point) == expected);
        }
    }
    CHECK(counts[0]);
    CHECK(counts[1]);
    CHECK(counts[2]);
    CHECK(exactProdFiber(0) == referenceProdFiber(0));
    CHECK(exactProdFiber(std::numeric_limits<std::uint32_t>::max()) ==
          referenceProdFiber(std::numeric_limits<std::uint32_t>::max()));
}

TEST("exact multiplication fibers match exhaustive byte oracle")
{
    auto random = std::mt19937{20261115};
    for (auto i = 0; i < 10000; ++i)
    {
        const auto difference = static_cast<std::uint32_t>(random());
        CHECK(exactProdFiber(difference) == referenceProdFiber(difference));
    }
}

TEST("exact multiplication fibers preserve attack candidate order")
{
    auto random = std::mt19937{20261116};
    for (auto i = 0; i < 10000; ++i)
    {
        const auto prod       = static_cast<std::uint32_t>(random());
        const auto known      = static_cast<std::uint32_t>(random()) & mask<24, 32>;
        auto       root       = std::vector<std::uint8_t>{};
        const auto rootBucket = static_cast<std::uint8_t>(msb(known) - msb(prod));
        for (auto x = std::uint32_t{}; x < 256; ++x)
            if ((msb(x * MultTab::multInv) == rootBucket || msb(x * MultTab::multInv) == (rootBucket + 255) % 256 ||
                 msb(x * MultTab::multInv) == (rootBucket + 1) % 256) &&
                prod + MultTab::multInv * x - known <= maxdiff<24>)
                root.push_back(x);
        CHECK(exactProdFiber(maxdiff<24> + known - prod) == root);

        auto       inner       = std::vector<std::uint8_t>{};
        const auto innerBucket = msb(prod - known);
        for (auto x = std::uint32_t{}; x < 256; ++x)
            if ((msb(x * MultTab::multInv) == innerBucket || msb(x * MultTab::multInv) == (innerBucket + 255) % 256) &&
                prod - MultTab::multInv * x - known <= maxdiff<24>)
                inner.push_back(x);
        CHECK(exactProdFiber(prod - known) == inner);
    }
}

TEST("forward multiplication fibers across every constant interval")
{
    auto points = std::vector<std::uint64_t>{0, std::uint64_t{1} << 32};
    for (auto value = std::uint32_t{}; value < 256; ++value)
    {
        points.push_back(value * MultTab::mult);
        points.push_back(std::uint32_t{value * MultTab::mult + (1u << 24)});
    }
    std::ranges::sort(points);
    points.erase(std::unique(points.begin(), points.end()), points.end());

    auto counts = std::array<bool, 3>{};
    for (auto i = std::size_t{}; i + 1 < points.size(); ++i)
    {
        const auto begin    = points[i];
        const auto end      = points[i + 1] - 1;
        const auto expected = referenceForwardFiber(begin);
        CHECK(expected.size() <= 2);
        counts[expected.size()] = true;
        for (const auto point : {begin, begin + (end - begin) / 2, end})
        {
            CHECK(referenceForwardFiber(point) == expected);
            CHECK(forwardFiber(point) == expected);
        }
    }
    CHECK(counts[0]);
    CHECK(counts[1]);
    CHECK(counts[2]);
}

TEST("forward multiplication fibers at arithmetic boundaries")
{
    constexpr auto gridStep = 32 * MultTab::mult;
    for (auto cell = std::uint32_t{}; cell < 32; ++cell)
        for (const auto delta : {0u, 1u, std::numeric_limits<std::uint32_t>::max()})
        {
            const auto boundary = (cell << 27) + delta;
            CHECK(forwardFiber(boundary) == referenceForwardFiber(boundary));
            for (auto quotient = std::uint32_t{}; quotient <= 8; ++quotient)
            {
                const auto point = MultTab::mult * cell + quotient * gridStep + delta;
                CHECK(forwardFiber(point) == referenceForwardFiber(point));
            }
        }
}

TEST("forward multiplication fibers match exhaustive byte oracle")
{
    auto random = std::mt19937{20261116};
    for (auto i = 0; i < 10000; ++i)
    {
        const auto difference = static_cast<std::uint32_t>(random());
        CHECK(forwardFiber(difference) == referenceForwardFiber(difference));
    }
}

TEST("forward multiplication fibers restore Y states")
{
    auto random = std::mt19937{20261117};
    for (auto i = 0; i < 10000; ++i)
    {
        const auto y     = static_cast<std::uint32_t>(random());
        const auto value = static_cast<std::uint32_t>(random()) & mask<0, 8>;
        const auto next  = MultTab::mult * (y + value) + 1;
        const auto base  = MultTab::mult * y + 1;
        const auto upper = (next & mask<24, 32>)+mask<0, 24>;
        const auto fiber = forwardFiber(upper - base);
        CHECK(fiber == referenceForwardFiber(upper - base));
        CHECK(std::ranges::find(fiber, value) != fiber.end());
        for (const auto candidate : fiber)
            CHECK(msb(base + MultTab::mult * candidate) == msb(next));
    }
}
