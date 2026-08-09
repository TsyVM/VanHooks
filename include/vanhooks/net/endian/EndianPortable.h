#pragma once

// Portable big/little-endian-to-host conversions.
//
// Linux (glibc/musl) and the BSDs/macOS already provide be16toh/be32toh/
// be64toh/le16toh/le32toh/le64toh (and the hto* inverses) as macros via
// <endian.h> or <sys/endian.h> / <machine/endian.h> — those are used as-is.
// Where the platform doesn't provide them (MSVC), fall back to C++23's
// <bit> (std::endian, std::byteswap), which is what makes a hand-rolled
// per-platform macro chain unnecessary here.

#include <cstdint>

#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__CYGWIN__)
	#include <endian.h>
#elif defined(__APPLE__)
	#include <machine/endian.h>
	#include <libkern/OSByteOrder.h>
	#if !defined(be16toh)
		#if __DARWIN_BYTE_ORDER == __DARWIN_BIG_ENDIAN
			#define be16toh(x) (x)
			#define be32toh(x) (x)
			#define be64toh(x) (x)
			#define le16toh(x) OSSwapInt16(x)
			#define le32toh(x) OSSwapInt32(x)
			#define le64toh(x) OSSwapInt64(x)
		#else
			#define be16toh(x) OSSwapInt16(x)
			#define be32toh(x) OSSwapInt32(x)
			#define be64toh(x) OSSwapInt64(x)
			#define le16toh(x) (x)
			#define le32toh(x) (x)
			#define le64toh(x) (x)
		#endif
	#endif
#endif

#if !defined(be16toh) || !defined(be32toh) || !defined(be64toh) || !defined(le16toh) || !defined(le32toh) || !defined(le64toh)

#include <bit>
#include <concepts>

namespace vanhooks::net::detail {

template <std::unsigned_integral T>
constexpr T byteswap_if_native_little(T value) noexcept {
	if constexpr (std::endian::native == std::endian::little) {
		return std::byteswap(value);
	} else {
		return value;
	}
}

template <std::unsigned_integral T>
constexpr T byteswap_if_native_big(T value) noexcept {
	if constexpr (std::endian::native == std::endian::big) {
		return std::byteswap(value);
	} else {
		return value;
	}
}

} // namespace vanhooks::net::detail

#ifndef be16toh
constexpr std::uint16_t be16toh(std::uint16_t value) noexcept { return vanhooks::net::detail::byteswap_if_native_little(value); }
#endif
#ifndef be32toh
constexpr std::uint32_t be32toh(std::uint32_t value) noexcept { return vanhooks::net::detail::byteswap_if_native_little(value); }
#endif
#ifndef be64toh
constexpr std::uint64_t be64toh(std::uint64_t value) noexcept { return vanhooks::net::detail::byteswap_if_native_little(value); }
#endif
#ifndef le16toh
constexpr std::uint16_t le16toh(std::uint16_t value) noexcept { return vanhooks::net::detail::byteswap_if_native_big(value); }
#endif
#ifndef le32toh
constexpr std::uint32_t le32toh(std::uint32_t value) noexcept { return vanhooks::net::detail::byteswap_if_native_big(value); }
#endif
#ifndef le64toh
constexpr std::uint64_t le64toh(std::uint64_t value) noexcept { return vanhooks::net::detail::byteswap_if_native_big(value); }
#endif

#endif // fallback needed

#ifndef htobe16
#define htobe16(x) be16toh(x)
#endif
#ifndef htobe32
#define htobe32(x) be32toh(x)
#endif
#ifndef htobe64
#define htobe64(x) be64toh(x)
#endif
#ifndef htole16
#define htole16(x) le16toh(x)
#endif
#ifndef htole32
#define htole32(x) le32toh(x)
#endif
#ifndef htole64
#define htole64(x) le64toh(x)
#endif
