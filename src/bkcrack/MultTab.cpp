#include "bkcrack/MultTab.hpp"

#include <algorithm>

const MultTab MultTab::instance;

MultTab::MultTab()
{
    // A byte enters its fiber at x*multInv and leaves at x*multInv + maxdiff<24> + 1.
    // Arithmetic wraps modulo 2^32, including intervals crossing zero.
    auto changes = std::array<std::vector<std::uint32_t>, 256>{};
    for (auto x = std::uint32_t{}; x < 256; ++x)
        for (const auto point : {x * multInv, x * multInv + maxdiff<24> + 1})
            if (point & mask<0, 24>)
                changes[msb(point)].push_back(point & mask<0, 24>);

    const auto fiber = [](std::uint32_t difference)
    {
        auto result = ProdFiber{};
        for (auto x = std::uint32_t{}; x < 256; ++x)
            if (difference - x * multInv <= maxdiff<24>)
            {
                if (result.count == result.values.size())
                    throw std::logic_error{"Too many exact multiplication fiber candidates."};
                result.values[result.count++] = x;
            }
        return result;
    };

    for (auto high = std::uint32_t{}; high < 256; ++high)
    {
        auto& points = changes[high];
        std::ranges::sort(points);
        points.erase(std::unique(points.begin(), points.end()), points.end());
        if (points.size() > 3)
            throw std::logic_error{"Too many exact multiplication fiber boundaries."};

        auto& bucket     = exactprodfiber[high];
        bucket.values[0] = fiber(high << 24);
        for (auto i = std::size_t{}; i < points.size(); ++i)
        {
            bucket.cuts[i]       = points[i];
            bucket.values[i + 1] = fiber((high << 24) | points[i]);
        }
    }
}
