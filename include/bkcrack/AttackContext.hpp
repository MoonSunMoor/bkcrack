#ifndef BKCRACK_ATTACKCONTEXT_HPP
#define BKCRACK_ATTACKCONTEXT_HPP

#include <bkcrack/types.hpp>

#include <cstddef>
#include <optional>

/// Constraints for one completed Z path; pass as const for the entire synchronous search.
struct ZPathContext
{
    std::size_t                  index{};        ///< Attack window offset in Data::plaintext and Data::keystream
    std::array<std::uint32_t, 8> z{};            ///< Z path, with the same known bits as the Z search
    std::array<std::uint32_t, 6> yHigh{};        ///< Y2..Y7[24,32), stored in their original bit positions
    std::uint32_t                y1Constraint{}; ///< Known Y1[26,32)
    std::uint8_t                 x3PlaintextBias{};
    std::optional<std::uint8_t>  nextKeystream; ///< Present only for a known contiguous byte after the window
};

/// Filtered candidate belonging to the accompanying ZPathContext, not a recovered key.
/// Consume synchronously: the producer retains ownership of the context and candidate.
struct AttackCandidate
{
    std::uint32_t y3{};
    std::uint32_t y7{};
    std::uint32_t packedX{}; ///< low8(X4), low8(X5), low8(X6), low8(X7), from least to most significant byte
};

#endif // BKCRACK_ATTACKCONTEXT_HPP
