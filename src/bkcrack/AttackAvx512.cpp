#include "bkcrack/Attack.hpp"

#include <bkcrack/MultTab.hpp>

#include <bit>
#include <immintrin.h>

namespace
{
constexpr auto multInv        = MultTab::multInv;
constexpr auto multInvSquared = multInv * multInv;
constexpr auto fiberWidth     = maxdiff<24>;

// The two neighboring residues contain every byte satisfying d - multInv * u <= fiberWidth.
static_assert(311ull * multInv == 264ull * (1ull << 32) - 3796725);
static_assert((264 * 86) % 311 == 1);
static_assert(2 * 311ull * fiberWidth < 3ull * (1ull << 32));
static_assert(2 * 3796725ull * 255 < (1ull << 32));
static_assert(310u * (311u * 18123u - 86u * 65536u) < 65536u);

auto broadcast(std::uint32_t value) -> __m512i
{
    return _mm512_set1_epi32(static_cast<int>(value));
}

struct ArithmeticFiber
{
    __m512i   first, second;
    __mmask16 keepFirst, keepSecond;
};

auto getArithmeticFiber(__m512i difference) -> ArithmeticFiber
{
    const auto even = _mm512_mul_epu32(difference, broadcast(311));
    const auto odd  = _mm512_mul_epu32(_mm512_srli_epi64(difference, 32), broadcast(311));
    const auto t    = _mm512_mask_blend_epi32(0xaaaa, _mm512_srli_epi64(even, 32), odd);
    const auto low  = _mm512_mullo_epi32(difference, broadcast(311));

    // t <= 310; the 16-bit reciprocal gives (86 * t) % 311 exactly.
    const auto quotient = _mm512_mulhi_epu16(t, _mm512_set1_epi16(18123));
    const auto first    = _mm512_sub_epi16(_mm512_mullo_epi16(t, _mm512_set1_epi16(86)),
                                           _mm512_mullo_epi16(quotient, _mm512_set1_epi16(311)));
    const auto negative = _mm512_cmplt_epu32_mask(low, broadcast(0x80000000u));
    const auto raw      = _mm512_add_epi32(first, _mm512_mask_blend_epi32(negative, broadcast(86), broadcast(225)));
    const auto wrap     = _mm512_cmpge_epu32_mask(raw, broadcast(311));
    const auto second   = _mm512_sub_epi32(raw, _mm512_maskz_mov_epi32(wrap, broadcast(311)));

    const auto residualFirst = _mm512_sub_epi32(difference, _mm512_mullo_epi32(first, broadcast(multInv)));
    const auto correction =
        _mm512_sub_epi32(_mm512_mask_blend_epi32(negative, broadcast(multInv * 86), broadcast(multInv * 225)),
                         _mm512_maskz_mov_epi32(wrap, broadcast(multInv * 311)));
    const auto      residualSecond = _mm512_sub_epi32(residualFirst, correction);
    const __mmask16 keepFirst =
        _mm512_cmplt_epu32_mask(first, broadcast(256)) & _mm512_cmple_epu32_mask(residualFirst, broadcast(fiberWidth));
    const __mmask16 keepSecond = _mm512_cmplt_epu32_mask(second, broadcast(256)) &
                                 _mm512_cmple_epu32_mask(residualSecond, broadcast(fiberWidth));
    return {first, second, keepFirst, keepSecond};
}

// Generate the four low-X3 linear maps from CRC's bitwise definition at compile time.
constexpr auto crc32(std::uint32_t x) -> std::uint32_t
{
    for (auto i = 0; i < 8; ++i)
        x = (x >> 1) ^ ((x & 1) ? 0xedb88320u : 0u);
    return x;
}

constexpr auto crc32inv(std::uint32_t x) -> std::uint32_t
{
    for (auto i = 0; i < 8; ++i)
    {
        const auto high = x >> 31;
        x               = ((x ^ (high ? 0xedb88320u : 0u)) << 1) | high;
    }
    return x;
}

constexpr auto x3Matrices = []
{
    auto matrices = std::array<std::uint64_t, 4>{};
    for (auto byte = 0; byte < 4; ++byte)
        for (auto bit = 0; bit < 8; ++bit)
        {
            auto low  = std::array<std::uint8_t, 4>{};
            low[byte] = 1u << bit;
            auto x    = std::uint32_t{low[0]};
            for (auto i = 1; i < 4; ++i)
                x = (crc32(x) & mask<8, 32>) | low[i];
            for (auto i = 0; i < 4; ++i)
                x = crc32inv(x);
            for (auto row = 0; row < 8; ++row)
                matrices[byte] |= std::uint64_t{(x >> row) & 1} << ((7 - row) * 8 + bit);
        }
    return matrices;
}();

auto projectX3(__m512i packed, std::uint8_t bias) -> __m512i
{
    auto low = _mm512_gf2p8affine_epi64_epi8(packed, _mm512_set1_epi64(x3Matrices[0]), 0);
    low      = _mm512_xor_si512(
        low, _mm512_gf2p8affine_epi64_epi8(_mm512_srli_epi32(packed, 8), _mm512_set1_epi64(x3Matrices[1]), 0));
    low = _mm512_xor_si512(
        low, _mm512_gf2p8affine_epi64_epi8(_mm512_srli_epi32(packed, 16), _mm512_set1_epi64(x3Matrices[2]), 0));
    low = _mm512_xor_si512(
        low, _mm512_gf2p8affine_epi64_epi8(_mm512_srli_epi32(packed, 24), _mm512_set1_epi64(x3Matrices[3]), 0));
    return _mm512_and_si512(_mm512_xor_si512(low, broadcast(bias)), broadcast(255));
}

// Bits 0..4 indicate a pending alternative at the root or one of the four Y depths.
// Resume the deepest alternative before fetching the lane's next stride-16 root guess.
struct SearchState
{
    __m512i next             = _mm512_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m512i pending          = _mm512_setzero_si512();
    __m512i root             = _mm512_setzero_si512();
    __m512i rootAlternative  = _mm512_setzero_si512();
    __m512i packed           = _mm512_setzero_si512();
    __m512i alternativeBytes = _mm512_setzero_si512();
    __m512i child6 = _mm512_setzero_si512(), child5 = _mm512_setzero_si512();
    __m512i child4 = _mm512_setzero_si512(), child3 = _mm512_setzero_si512();

    template <int Depth>
    void step(__m512i& current, __m512i& alternative, __mmask16& active, __m512i start, const ZPathContext& context)
    {
        static_assert(Depth >= 1 && Depth <= 4);
        constexpr auto  shift         = 8 * (4 - Depth);
        constexpr auto  bit           = 1u << Depth;
        const __mmask16 fresh         = active & _mm512_cmplt_epu32_mask(start, broadcast(Depth));
        const __mmask16 resume        = active & _mm512_cmpeq_epi32_mask(start, broadcast(Depth));
        const __mmask16 participating = fresh | resume;

        const auto      fy         = _mm512_mullo_epi32(_mm512_sub_epi32(current, broadcast(1)), broadcast(multInv));
        const auto      difference = _mm512_sub_epi32(_mm512_mullo_epi32(current, broadcast(multInvSquared)),
                                                      broadcast(multInvSquared + multInv + context.yHigh[4 - Depth]));
        const auto      fiber      = getArithmeticFiber(difference);
        const auto      high       = broadcast(context.yHigh[5 - Depth]);
        const __mmask16 keepFirst =
            fresh & fiber.keepFirst &
            _mm512_cmplt_epu32_mask(_mm512_sub_epi32(_mm512_sub_epi32(fy, fiber.first), high), broadcast(1u << 24));
        const __mmask16 keepSecond =
            fresh & fiber.keepSecond &
            _mm512_cmplt_epu32_mask(_mm512_sub_epi32(_mm512_sub_epi32(fy, fiber.second), high), broadcast(1u << 24));
        const __mmask16 both     = keepFirst & keepSecond;
        const __mmask16 accepted = keepFirst | keepSecond | resume;
        const auto      u =
            _mm512_mask_blend_epi32(resume, _mm512_mask_blend_epi32(keepFirst, fiber.second, fiber.first),
                                    _mm512_and_si512(_mm512_srli_epi32(alternativeBytes, shift), broadcast(255)));
        const auto child = _mm512_mask_blend_epi32(resume, _mm512_sub_epi32(fy, u), alternative);

        pending             = _mm512_mask_blend_epi32(participating, pending,
                                                      _mm512_or_si512(_mm512_andnot_si512(broadcast(bit), pending),
                                                                      _mm512_maskz_mov_epi32(both, broadcast(bit))));
        alternative         = _mm512_mask_blend_epi32(both, alternative, _mm512_sub_epi32(fy, fiber.second));
        const auto byteMask = broadcast(255u << shift);
        alternativeBytes    = _mm512_mask_blend_epi32(
            both, alternativeBytes,
            _mm512_or_si512(_mm512_andnot_si512(byteMask, alternativeBytes), _mm512_slli_epi32(fiber.second, shift)));
        packed = _mm512_mask_blend_epi32(
            accepted, packed, _mm512_or_si512(_mm512_andnot_si512(byteMask, packed), _mm512_slli_epi32(u, shift)));
        current = _mm512_mask_blend_epi32(accepted, current, child);
        active  = (active & ~participating) | accepted;
    }
};
} // namespace

void Attack::exploreYlistsAvx512(const ZPathContext& context)
{
    auto       state     = SearchState{};
    const auto rootHigh  = broadcast(context.yHigh[5]);
    const auto rootBound = broadcast(fiberWidth + context.yHigh[4]);
    while (true)
    {
        const auto      pending = _mm512_test_epi32_mask(state.pending, state.pending);
        const __mmask16 fetch   = ~pending & _mm512_cmplt_epu32_mask(state.next, broadcast(65536));
        auto            active  = static_cast<__mmask16>(pending | fetch);
        if (!active)
            break;

        auto start                 = _mm512_sub_epi32(broadcast(31), _mm512_lzcnt_epi32(state.pending));
        start                      = _mm512_maskz_mov_epi32(pending, start);
        const __mmask16 resumeRoot = pending & _mm512_cmpeq_epi32_mask(start, _mm512_setzero_si512());
        const __mmask16 rootWork   = fetch | resumeRoot;
        const auto      base       = _mm512_or_si512(rootHigh, _mm512_slli_epi32(state.next, 8));
        state.next                 = _mm512_mask_add_epi32(state.next, fetch, state.next, broadcast(16));
        const auto fiber           = getArithmeticFiber(
            _mm512_sub_epi32(rootBound, _mm512_mullo_epi32(_mm512_sub_epi32(base, broadcast(1)), broadcast(multInv))));
        const __mmask16 keepFirst  = fetch & fiber.keepFirst;
        const __mmask16 keepSecond = fetch & fiber.keepSecond;
        const __mmask16 both       = keepFirst & keepSecond;
        const __mmask16 accepted   = keepFirst | keepSecond | resumeRoot;
        const auto generated = _mm512_or_si512(base, _mm512_mask_blend_epi32(keepFirst, fiber.second, fiber.first));
        state.root           = _mm512_mask_blend_epi32(accepted, state.root,
                                                       _mm512_mask_blend_epi32(resumeRoot, generated, state.rootAlternative));
        state.rootAlternative =
            _mm512_mask_blend_epi32(both, state.rootAlternative, _mm512_or_si512(base, fiber.second));
        state.pending = _mm512_mask_blend_epi32(rootWork, state.pending, _mm512_maskz_mov_epi32(both, broadcast(1)));
        state.packed  = _mm512_mask_mov_epi32(state.packed, accepted, _mm512_setzero_si512());
        active        = (active & ~rootWork) | accepted;

        auto current = state.root;
        state.step<1>(current, state.child6, active, start, context);
        state.step<2>(current, state.child5, active, start, context);
        state.step<3>(current, state.child4, active, start, context);
        state.step<4>(current, state.child3, active, start, context);

        const auto x3        = projectX3(state.packed, context.x3PlaintextBias);
        const auto bound     = _mm512_sub_epi32(_mm512_sub_epi32(_mm512_mullo_epi32(current, broadcast(multInvSquared)),
                                                                 _mm512_mullo_epi32(x3, broadcast(multInv))),
                                                broadcast(multInvSquared + multInv + context.y1Constraint));
        auto       survivors = static_cast<__mmask16>(active & _mm512_cmple_epu32_mask(bound, broadcast(maxdiff<26>)));
        if (survivors)
        {
            alignas(64) auto y3      = std::array<std::uint32_t, 16>{};
            alignas(64) auto y7      = std::array<std::uint32_t, 16>{};
            alignas(64) auto packedX = std::array<std::uint32_t, 16>{};
            _mm512_store_si512(y3.data(), current);
            _mm512_store_si512(y7.data(), state.root);
            _mm512_store_si512(packedX.data(), state.packed);
            do
            {
                const auto lane = std::countr_zero(survivors);
                verifyXlist(context, AttackCandidate{y3[lane], y7[lane], packedX[lane]});
                survivors &= survivors - 1;
            } while (survivors);
        }
    }
}
