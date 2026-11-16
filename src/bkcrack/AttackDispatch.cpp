#include "bkcrack/Attack.hpp"

#ifdef BKCRACK_HAS_AVX512
#include "AttackAvx512.hpp"
#endif

#include <algorithm>
#include <atomic>
#include <thread>

#if defined(BKCRACK_HAS_AVX512) && defined(_MSC_VER)
#include <intrin.h>
#endif

namespace
{
#ifdef BKCRACK_HAS_AVX512
auto isAvx512Supported() -> bool
{
#ifdef _MSC_VER
    auto cpu = std::array<int, 4>{};
    __cpuidex(cpu.data(), 0, 0);
    if (cpu[0] < 7)
        return false;

    __cpuidex(cpu.data(), 1, 0);
    // Require FMA, POPCNT, XSAVE, OSXSAVE and AVX before reading XCR0.
    constexpr auto avx = (1u << 12) | (1u << 23) | (1u << 26) | (1u << 27) | (1u << 28);
    if ((static_cast<unsigned>(cpu[2]) & avx) != avx)
        return false;

    // XMM, YMM, opmask and both ZMM register components must be saved by the OS.
    if ((_xgetbv(0) & 0xe6) != 0xe6)
        return false;

    __cpuidex(cpu.data(), 7, 0);
    // MSVC also enables BMI1, AVX2, BMI2, AVX512DQ and AVX512VL for this file.
    constexpr auto avx512 =
        (1u << 3) | (1u << 5) | (1u << 8) | (1u << 16) | (1u << 17) | (1u << 28) | (1u << 30) | (1u << 31);
    if ((static_cast<unsigned>(cpu[1]) & avx512) != avx512 || (cpu[2] & (1 << 8)) == 0) // GFNI
        return false;

    // LZCNT can also be emitted by the compiler under /arch:AVX512.
    __cpuidex(cpu.data(), static_cast<int>(0x80000000u), 0);
    if (static_cast<unsigned>(cpu[0]) < 0x80000001u)
        return false;
    __cpuidex(cpu.data(), static_cast<int>(0x80000001u), 0);
    return (cpu[2] & (1 << 5)) != 0;
#else
    return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
           __builtin_cpu_supports("avx512cd") && __builtin_cpu_supports("gfni");
#endif
}

#endif

template <class Worker>
auto runAttack(const Data& data, const std::vector<std::uint32_t>& zi_2_32_vector, int& start, std::size_t index,
               int jobs, const bool exhaustive, Progress& progress) -> std::vector<Keys>
{
    const auto* candidates = zi_2_32_vector.data();
    const auto  size       = static_cast<int>(zi_2_32_vector.size());

    auto solutions      = std::vector<Keys>{};
    auto solutionsMutex = std::mutex{};
    auto worker         = Worker{data, index, solutions, solutionsMutex, exhaustive, progress};

    progress.done  = start;
    progress.total = size;

    const auto threadCount        = std::clamp(jobs, 1, size);
    auto       threads            = std::vector<std::thread>{};
    auto       nextCandidateIndex = std::atomic<int>{start};
    for (auto i = 0; i < threadCount; ++i)
        threads.emplace_back(
            [&nextCandidateIndex, size, &progress, candidates, worker]() mutable
            {
                for (auto i = nextCandidateIndex++; i < size; i = nextCandidateIndex++)
                {
                    worker.carryout(candidates[i]);
                    progress.done++;

                    if (progress.state != Progress::State::Normal)
                        break;
                }
            });
    for (auto& thread : threads)
        thread.join();

    start = std::min(nextCandidateIndex.load(), size);

    return solutions;
}
} // namespace

auto attack(const Data& data, const std::vector<std::uint32_t>& zi_2_32_vector, int& start, std::size_t index, int jobs,
            bool exhaustive, Progress& progress) -> std::vector<Keys>
{
#ifdef BKCRACK_HAS_AVX512
    if (isAvx512Supported())
        return runAttack<AttackAvx512>(data, zi_2_32_vector, start, index, jobs, exhaustive, progress);
#endif
    return runAttack<Attack>(data, zi_2_32_vector, start, index, jobs, exhaustive, progress);
}
