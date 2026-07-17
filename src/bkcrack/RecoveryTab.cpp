#include "bkcrack/RecoveryTab.hpp"

#include <bkcrack/Crc32Tab.hpp>
#include <bkcrack/MultTab.hpp>

RecoveryTab::RecoveryTab(const std::vector<std::uint8_t>& charset)
: rowStride{(charset.size() + 15) / 16 * 16}
, storage(256 * rowStride + 15)
{
    const auto misalignment = reinterpret_cast<std::uintptr_t>(storage.data()) % 64;
    firstValueOffset        = (64 - misalignment) % 64 / sizeof(std::uint32_t);

    auto* values = storage.data() + firstValueOffset;
    for (auto x0PartialLow = std::uint32_t{}; x0PartialLow < 256; ++x0PartialLow)
        for (auto candidateIndex = std::size_t{}; candidateIndex < charset.size(); ++candidateIndex)
        {
            const auto x0Low = x0PartialLow ^ lsb(Crc32Tab::crc32(0, charset[candidateIndex]));
            values[x0PartialLow * rowStride + candidateIndex] = MultTab::mult * x0Low;
        }
}
