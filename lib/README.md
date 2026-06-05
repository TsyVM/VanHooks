# VanHooks — Precompiled Libraries

Precompiled static libraries for Windows, built with MSVC and a static CRT
(`/MT` Release, `/MTd` Debug) so no Visual C++ Redistributable is required.
Zydis is compiled in — no separate dependency needed.

## Library Matrix

| Folder | Architecture | Config | CRT | NA |
|---|---|---|---|---|
| `win-x64/Release/vanhooks.lib` | x64 | Release | `/MT` | 
| `win-x86/Release/vanhooks.lib` | x86 (32-bit) | Release | `/MT` | 

> **ARM64:** Build from source — see below.  The ARM64 cross-compile tools
> were not available on the release build machine.

---

## Drop-In Usage — CMake

```cmake
# Pick the correct lib for your target architecture and config:
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(VH_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/win-x64")
else()
    set(VH_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib/win-x86")
endif()

add_library(VanHooks::vanhooks STATIC IMPORTED)
set_target_properties(VanHooks::vanhooks PROPERTIES
    IMPORTED_LOCATION_RELEASE "${VH_LIB_DIR}/Release/vanhooks.lib"
    IMPORTED_LOCATION_DEBUG   "${VH_LIB_DIR}/Debug/vanhooks.lib"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_link_libraries(my_target PRIVATE VanHooks::vanhooks)
```

---

## Drop-In Usage — MSVC Project

1. **Additional Include Directories** → add `include\`
2. **Additional Library Directories** → add `lib\win-x64\Release\` (adjust arch/config)
3. **Additional Dependencies** → add `vanhooks.lib`
4. **Runtime Library** → **Multi-threaded (`/MT`)** for Release, **Multi-threaded Debug (`/MTd`)** for Debug
   *(must match the precompiled lib's CRT linkage)*

---

## Build from Source (ARM64 / custom CRT / Linux / macOS)

```bash
# Windows ARM64 (requires VS ARM64 build tools installed)
cmake -B build -G "Visual Studio 17 2022" -A ARM64 ^
      -DVH_BUILD_TESTS=OFF -DVH_BUILD_EXAMPLES=OFF
cmake --build build --config Release
# → build\Release\vanhooks.lib

# Linux / macOS
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
# → build/libvanhooks.a
```
