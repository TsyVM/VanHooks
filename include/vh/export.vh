#pragma once

/**
 * vh/export.vh — Shared library export/import macros
 *
 * When VanHooks is built as a shared library (VH_BUILD_SHARED=ON),
 * these macros mark public symbols for export/import.
 *
 * Compile definitions (set automatically by CMake):
 *   VH_SHARED   — defined when building or consuming a shared VanHooks
 *   VH_EXPORTS  — defined only when BUILDING the shared library
 */

#if defined(VH_SHARED)
#   if defined(_WIN32)
#       if defined(VH_EXPORTS)
#           define VH_API __declspec(dllexport)
#       else
#           define VH_API __declspec(dllimport)
#       endif
#   elif defined(__GNUC__) || defined(__clang__)
#       define VH_API __attribute__((visibility("default")))
#   else
#       define VH_API
#   endif
#else
#   define VH_API
#endif
