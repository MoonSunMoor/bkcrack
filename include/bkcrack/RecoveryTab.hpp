#ifndef BKCRACK_RECOVERYTAB_HPP
#define BKCRACK_RECOVERYTAB_HPP

#include <bkcrack/types.hpp>

/// Precomputed lookup table for password recovery
class RecoveryTab
{
public:
    /// Initialize the lookup table for the given character set
    explicit RecoveryTab(const std::vector<std::uint8_t>& charset);

    RecoveryTab(const RecoveryTab&)                    = delete;
    auto operator=(const RecoveryTab&) -> RecoveryTab& = delete;

    /// \return Y0 contribution values for the given LSB(X0 partial)
    auto getY0DeltaRow(std::uint8_t x0PartialLow) const -> const std::uint32_t*
    {
        return storage.data() + firstValueOffset + x0PartialLow * rowStride;
    }

private:
    const std::size_t          rowStride;
    std::vector<std::uint32_t> storage;
    std::size_t                firstValueOffset{};
};

#endif // BKCRACK_RECOVERYTAB_HPP
