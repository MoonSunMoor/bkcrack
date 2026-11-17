# configure version header
set(VERSION_HEADER_CONFIGURED "${PROJECT_BINARY_DIR}/include/bkcrack/version.hpp")
configure_file("${PROJECT_SOURCE_DIR}/include/bkcrack/version.hpp.in" "${VERSION_HEADER_CONFIGURED}")

# list files
file(GLOB HEADERS "${PROJECT_SOURCE_DIR}/include/bkcrack/*.hpp")
file(GLOB SOURCES "*.cpp")
list(REMOVE_ITEM SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/AttackAvx512.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/AttackAvx512Kernel.cpp")

# add the library target
add_library(bkcrack-core)
target_sources(bkcrack-core
    PUBLIC FILE_SET HEADERS
    BASE_DIRS ${PROJECT_SOURCE_DIR}/include ${PROJECT_BINARY_DIR}/include
    FILES
        ${VERSION_HEADER_CONFIGURED}
        ${HEADERS}
    PRIVATE
        ${SOURCES}
)
target_enable_warnings(bkcrack-core)

# enable C++20
target_compile_features(bkcrack-core PUBLIC cxx_std_20)

# let CMake work out the system-specific details to use threads
find_package(Threads REQUIRED)
target_link_libraries(bkcrack-core PRIVATE Threads::Threads)

# Keep ISA-specific instructions out of the dispatcher and the portable scalar build.
option(BKCRACK_ENABLE_AVX512 "Build the AVX512 attack kernel when supported by the compiler." ON)
if(BKCRACK_ENABLE_AVX512 AND CMAKE_SIZEOF_VOID_P EQUAL 8
    AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64|amd64)$")
    if(MSVC)
        set(BKCRACK_AVX512_OPTIONS /arch:AVX512)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
            list(APPEND BKCRACK_AVX512_OPTIONS /clang:-mgfni)
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        set(BKCRACK_AVX512_OPTIONS -mavx512f -mavx512bw -mavx512cd -mgfni)
    endif()
    if(BKCRACK_AVX512_OPTIONS)
        include(CheckCXXSourceCompiles)
        include(CMakePushCheckState)
        cmake_push_check_state(RESET)
        # The dispatcher must compile without the kernel's ISA options.
        check_cxx_source_compiles([[
            #ifdef _MSC_VER
            #include <intrin.h>
            int main() {
                int cpu[4];
                __cpuidex(cpu, 0, 0);
                return cpu[0] ^ static_cast<int>(_xgetbv(0));
            }
            #else
            int main() {
                return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512bw") &&
                    __builtin_cpu_supports("avx512cd") && __builtin_cpu_supports("gfni");
            }
            #endif]] BKCRACK_CAN_DETECT_AVX512)
        string(JOIN " " CMAKE_REQUIRED_FLAGS ${BKCRACK_AVX512_OPTIONS})
        check_cxx_source_compiles([[
            #include <immintrin.h>
            int main() {
                auto x = _mm512_set1_epi32(1);
                x = _mm512_lzcnt_epi32(x);
                x = _mm512_mulhi_epu16(x, x);
                x = _mm512_gf2p8affine_epi64_epi8(x, x, 0);
                return _mm512_cmpeq_epi32_mask(x, x) == 0;
            }]] BKCRACK_CAN_BUILD_AVX512)
        cmake_pop_check_state()
        if(BKCRACK_CAN_DETECT_AVX512 AND BKCRACK_CAN_BUILD_AVX512)
            target_sources(bkcrack-core PRIVATE AttackAvx512.cpp AttackAvx512Kernel.cpp AttackAvx512.hpp)
            set_source_files_properties(AttackAvx512Kernel.cpp PROPERTIES
                COMPILE_OPTIONS "${BKCRACK_AVX512_OPTIONS}")
            target_compile_definitions(bkcrack-core PRIVATE BKCRACK_HAS_AVX512)
            message(STATUS "AVX512 attack kernel enabled with runtime CPU detection")
        endif()
    endif()
endif()
