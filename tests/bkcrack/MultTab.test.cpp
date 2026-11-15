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
