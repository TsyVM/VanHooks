#pragma once

// ===== Consolidated header: Common.h =====
// Merges: DeprecationUtils, MacAddress, IpAddress, IpAddressUtils, IpUtils, GeneralUtils, SystemUtils, Logger, TablePrinter, PointerVector, LRUList, TimespecTimeval, VersionInfo, OUILookup, md5
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

// ---- begin DeprecationUtils.h ----
/// @file

#ifndef VH_DEPRECATED
#	if defined(__GNUC__) || defined(__clang__)
#		define VH_DEPRECATED(msg) __attribute__((deprecated(msg)))
#	elif defined(_MSC_VER)
#		define VH_DEPRECATED(msg) __declspec(deprecated(msg))
#	else
#		pragma message("WARNING: DEPRECATED feature is not implemented for this compiler")
#		define VH_DEPRECATED(msg)
#	endif
#endif

#if !defined(DISABLE_WARNING_PUSH) || !defined(DISABLE_WARNING_POP)
#	if defined(_MSC_VER)
#		define DISABLE_WARNING_PUSH __pragma(warning(push))
#		define DISABLE_WARNING_POP __pragma(warning(pop))
#		define DISABLE_WARNING(warningNumber) __pragma(warning(disable : warningNumber))

#		define DISABLE_WARNING_DEPRECATED DISABLE_WARNING(4996)
#	elif defined(__GNUC__) || defined(__clang__)
#		define DO_PRAGMA(X) _Pragma(#X)
#		define DISABLE_WARNING_PUSH DO_PRAGMA(GCC diagnostic push)
#		define DISABLE_WARNING_POP DO_PRAGMA(GCC diagnostic pop)
#		define DISABLE_WARNING(warningName) DO_PRAGMA(GCC diagnostic ignored #warningName)

// clang-format off
#		define DISABLE_WARNING_DEPRECATED DISABLE_WARNING(-Wdeprecated-declarations)
// clang-format on
#	else
#		pragma message("WARNING: Disabling of warnings is not implemented for this compiler")
#		define DISABLE_WARNING_PUSH
#		define DISABLE_WARNING_POP

#		define DISABLE_WARNING_DEPRECATED
#	endif
#endif
// ---- end DeprecationUtils.h ----

// ---- begin MacAddress.h ----
#include <algorithm>
#include <initializer_list>
#include <iterator>
#include <ostream>
#include <stdint.h>
#include <string.h>
#include <string>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class MacAddress
	 * Represents L2 MAC addresses. Can be constructed from string or a series of 6 byte octets
	 */
	class MacAddress
	{
	public:
		/**
		 * Default constructor for this class.
		 * Initializes the address as 00:00:00:00:00:00.
		 */
		MacAddress() = default;

		/**
		 * A constructor that creates an instance of the class out of a byte array.
		 * The byte array length should be 6 (as MAC address is 6-byte long), and the remaining bytes are ignored.
		 * If the byte array is invalid, the constructor throws an exception.
		 * @param[in] addr A pointer to the byte array containing 6 bytes representing the MAC address
		 */
		explicit MacAddress(const uint8_t* addr)
		{
			memcpy(address_, addr, sizeof(address_));
		}

		/**
		 * A constructor that creates an instance of the class out of a std::string.
		 * If the string doesn't represent a valid MAC address, the constructor throws an exception.
		 * @param[in] addr the string representing the MAC address in format "00:00:00:00:00:00"
		 */
		explicit MacAddress(const std::string& addr);

		/**
		 * A template constructor that creates an instance of the class out of a string convertible to std::string.
		 * If the string doesn't represent a valid MAC address, the constructor throws an exception.
		 * @param[in] addr the string representing the MAC address in format "00:00:00:00:00:00"
		 */
		template <typename T, typename = typename std::enable_if<std::is_convertible<T, std::string>::value>::type>
		MacAddress(const T& addr) : MacAddress(static_cast<std::string>(addr))
		{}

		/**
		 * A constructor that creates an instance of 6 bytes representing the MAC address
		 * @param[in] firstOctet Represent the first octet in the address
		 * @param[in] secondOctet Represent the second octet in the address
		 * @param[in] thirdOctet Represent the third octet in the address
		 * @param[in] fourthOctet Represent the fourth octet in the address
		 * @param[in] fifthOctet Represent the fifth octet in the address
		 * @param[in] sixthOctet Represent the sixth octet in the address
		 */
		inline MacAddress(uint8_t firstOctet, uint8_t secondOctet, uint8_t thirdOctet, uint8_t fourthOctet,
		                  uint8_t fifthOctet, uint8_t sixthOctet)
		{
			address_[0] = firstOctet;
			address_[1] = secondOctet;
			address_[2] = thirdOctet;
			address_[3] = fourthOctet;
			address_[4] = fifthOctet;
			address_[5] = sixthOctet;
		}

		/**
		 * A constructor that creates an instance out of the initializer list.
		 * The byte list length should be 6 (as MAC address is 6-byte long).
		 * If the list is invalid, the constructor throws an exception.
		 * @param[in] octets An initializer list containing the values of type uint8_t representing the MAC address
		 */
		MacAddress(std::initializer_list<uint8_t> octets)
		{
			if (octets.size() != sizeof(address_))
			{
				throw std::invalid_argument("Invalid initializer list size, should be 6");
			}
			std::copy(octets.begin(), octets.end(), std::begin(address_));
		}

		/**
		 * Overload of the comparison operator.
		 * @param[in] other The object to compare with
		 * @return True if addresses are equal, false otherwise
		 */
		bool operator==(const MacAddress& other) const
		{
			return memcmp(address_, other.address_, sizeof(address_)) == 0;
		}

		/**
		 * Overload of the not-equal operator
		 * @param[in] other The object to compare with
		 * @return True if addresses are not equal, false otherwise
		 */
		bool operator!=(const MacAddress& other) const
		{
			return !operator==(other);
		}

		/**
		 * Overload of the assignment operator.
		 * If the list is invalid, the constructor throws an exception.
		 * @param[in] octets An initializer list containing the values of type uint8_t representing the MAC address, the
		 * length of the list must be equal to 6
		 */
		MacAddress& operator=(std::initializer_list<uint8_t> octets)
		{
			if (octets.size() != sizeof(address_))
			{
				throw std::invalid_argument("Invalid initializer list size, should be 6");
			}

			std::copy(octets.begin(), octets.end(), std::begin(address_));
			return *this;
		}

		/**
		 * Returns the pointer to raw data
		 * @return The pointer to raw data
		 */
		const uint8_t* get_raw_data() const
		{
			return address_;
		}

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string to_string() const;

		/**
		 * Allocates a byte array of length 6 and copies address value into it. Array deallocation is user
		 * responsibility
		 * @param[in] arr A pointer to where array will be allocated
		 */
		void copy_to(uint8_t** arr) const
		{
			*arr = new uint8_t[sizeof(address_)];
			memcpy(*arr, address_, sizeof(address_));
		}

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * This method assumes array allocated size is at least 6 (the size of a MAC address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		void copy_to(uint8_t* arr) const
		{
			memcpy(arr, address_, sizeof(address_));
		}

		// ---- Legacy upstream-style aliases (source compat; prefer the snake_case API above) ----
		VH_DEPRECATED("use get_raw_data()")
		const uint8_t* getRawData() const { return get_raw_data(); }
		VH_DEPRECATED("use to_string()")
		std::string toString() const { return to_string(); }
		VH_DEPRECATED("use copy_to()")
		void copyTo(uint8_t** arr) const { copy_to(arr); }
		VH_DEPRECATED("use copy_to()")
		void copyTo(uint8_t* arr) const { copy_to(arr); }

		/**
		 * A static value representing a zero value of MAC address, meaning address of value "00:00:00:00:00:00"
		 */
		static MacAddress Zero;

	private:
		uint8_t address_[6] = { 0 };
	};
}  // namespace vanhooks::net

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::MacAddress& macAddress)
{
	os << macAddress.to_string();
	return os;
}
// ---- end MacAddress.h ----

// ---- begin IpAddress.h ----
#include <stdint.h>
#include <string.h>
#include <string>
#include <algorithm>
#include <ostream>
#include <array>
#include <memory>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	// forward declarations
	class IPv4Network;
	class IPv6Network;

	// The implementation of the classes is based on document N4771 "Working Draft, C++ Extensions for Networking"
	// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/n4771.pdf

	/**
	 * @class IPv4Address
	 * Represents an IPv4 address (of type XXX.XXX.XXX.XXX)
	 */
	class IPv4Address
	{
	public:
		/**
		 * A default constructor that creates an instance of the class with the zero-initialized address
		 */
		IPv4Address() = default;

		/**
		 * A constructor that creates an instance of the class out of 4-byte integer value.
		 * @param[in] addrAsInt The address as 4-byte integer in network byte order
		 */
		IPv4Address(const uint32_t addrAsInt)
		{
			memcpy(bytes_.data(), &addrAsInt, sizeof(addrAsInt));
		}

		/**
		 * A constructor that creates an instance of the class out of 4-byte array.
		 * @param[in] bytes The address as 4-byte array in network byte order
		 */
		IPv4Address(const uint8_t bytes[4])
		{
			memcpy(bytes_.data(), bytes, 4 * sizeof(uint8_t));
		}

		/**
		 * A constructor that creates an instance of the class out of a 4-byte standard array.
		 * @param[in] bytes The address as 4-byte standard array in network byte order
		 */
		IPv4Address(const std::array<uint8_t, 4>& bytes) : bytes_(bytes)
		{}

		/**
		 * A constructor that creates an instance of the class out of std::string value.
		 *
		 * @param[in] addrAsString The std::string representation of the address
		 * @throws std::invalid_argument The provided string does not represent a valid IPv4 address.
		 */
		IPv4Address(const std::string& addrAsString);

		/**
		 * @return A 4-byte integer in network byte order representing the IPv4 address
		 */
		inline uint32_t to_int() const;

		/**
		 * @return A non-owning pointer to 4-byte C-style array representing the IPv4 address
		 */
		const uint8_t* to_bytes() const
		{
			return bytes_.data();
		}

		/**
		 * @return A reference to a 4-byte standard array representing the IPv4 address
		 */
		const std::array<uint8_t, 4>& to_byte_array() const
		{
			return bytes_;
		}

		/**
		 * @return A string representation of the address
		 */
		std::string to_string() const;

		// ---- Legacy upstream-style aliases (source compat; prefer the snake_case API above) ----
		VH_DEPRECATED("use to_int()")
		uint32_t toInt() const { return to_int(); }
		VH_DEPRECATED("use to_bytes()")
		const uint8_t* toBytes() const { return to_bytes(); }
		VH_DEPRECATED("use to_string()")
		std::string toString() const { return to_string(); }

		/**
		 * @return True if an address is multicast, false otherwise.
		 */
		bool is_multicast() const;

		/**
		 * Overload of the equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are equal, false otherwise
		 */
		bool operator==(const IPv4Address& rhs) const
		{
			return to_int() == rhs.to_int();
		}

		/**
		 * Overload of the less-than operator
		 * @param[in] rhs The object to compare with
		 * @return True if the address value is lower than the other address value, false otherwise
		 */
		bool operator<(const IPv4Address& rhs) const
		{
			uint32_t intVal = to_int();
			std::reverse(reinterpret_cast<uint8_t*>(&intVal), reinterpret_cast<uint8_t*>(&intVal) + sizeof(intVal));

			uint32_t rhsIntVal = rhs.to_int();
			std::reverse(reinterpret_cast<uint8_t*>(&rhsIntVal),
			             reinterpret_cast<uint8_t*>(&rhsIntVal) + sizeof(rhsIntVal));

			return intVal < rhsIntVal;
		}

		/**
		 * Overload of the not-equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are not equal, false otherwise
		 */
		bool operator!=(const IPv4Address& rhs) const
		{
			return !(*this == rhs);
		}

		/**
		 * Checks whether the address matches a network.
		 * @param network An IPv4Network network
		 * @return True if the address matches the network or false otherwise
		 */
		bool match_network(const IPv4Network& network) const;

		/**
		 * Checks whether the address matches a network.
		 * For example: this method will return true for address 10.1.1.9 and network which is one of:
		 * 10.1.1.1/24, 10.1.1.1/255.255.255.0
		 * Another example: this method will return false for address 11.1.1.9 and network which is one of:
		 * 10.1.1.1/16, 10.1.1.1/255.255.0.0
		 * @param[in] network A string in one of these formats:
		 *  - X.X.X.X/Y where X.X.X.X is a valid IP address and Y is a number between 0 and 32
		 *  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IP address and Y.Y.Y.Y is a valid netmask
		 * @return True if the address matches the network or false if it doesn't or if the network is invalid
		 */
		bool match_network(const std::string& network) const;

		/**
		 * A static method that checks whether a string represents a valid IPv4 address
		 * @param[in] addrAsString The std::string representation of the address
		 * @return True if the address is valid, false otherwise
		 */
		static bool is_valid_ipv4_address(const std::string& addrAsString);

		/**
		 * A static value representing a zero value of IPv4 address, meaning address of value "0.0.0.0".
		 */
		static const IPv4Address Zero;

		/**
		 * A static values representing the lower and upper bound of IPv4 multicast ranges. The bounds are inclusive.
		 * MulticastRangeLowerBound is initialized to "224.0.0.0".
		 * MulticastRangeUpperBound is initialized to "239.255.255.255".
		 * In order to check whether the address is a multicast address the is_multicast method can be used.
		 */
		static const IPv4Address MulticastRangeLowerBound;
		static const IPv4Address MulticastRangeUpperBound;

	private:
		std::array<uint8_t, 4> bytes_ = { 0 };
	};  // class IPv4Address

	// Implementation of inline methods

	uint32_t IPv4Address::to_int() const
	{
		uint32_t addr;
		memcpy(&addr, bytes_.data(), bytes_.size() * sizeof(uint8_t));
		return addr;
	}

	/**
	 * @class IPv6Address
	 * Represents an IPv6 address (of type xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx).
	 */
	class IPv6Address
	{
	public:
		/**
		 * A default constructor that creates an instance of the class with the zero-initialized address.
		 */
		IPv6Address() = default;

		/**
		 * A constructor that creates an instance of the class out of 16-byte array.
		 * @param[in] bytes The address as 16-byte array in network byte order
		 */
		IPv6Address(const uint8_t bytes[16])
		{
			memcpy(bytes_.data(), bytes, 16 * sizeof(uint8_t));
		}

		/**
		 * A constructor that creates an instance of the class out of a 16-byte standard array.
		 * @param[in] bytes The address as 16-byte standard array in network byte order
		 */
		IPv6Address(const std::array<uint8_t, 16>& bytes) : bytes_(bytes)
		{}

		/**
		 * A constructor that creates an instance of the class out of std::string value.
		 *
		 * @param[in] addrAsString The std::string representation of the address
		 * @throws std::invalid_argument The provided string does not represent a valid IPv6 address.
		 */
		IPv6Address(const std::string& addrAsString);

		/**
		 * Returns a view of the IPv6 address as a 16-byte raw C-style array
		 * @return A non-owning pointer to 16-byte array representing the IPv6 address
		 */
		const uint8_t* to_bytes() const
		{
			return bytes_.data();
		}

		/**
		 * Returns a view of the IPv6 address as a std::array of bytes
		 * @return A reference to a 16-byte standard array representing the IPv6 address
		 */
		const std::array<uint8_t, 16>& to_byte_array() const
		{
			return bytes_;
		}

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string to_string() const;

		/**
		 * Determine whether the address is a multicast address
		 * @return True if an address is multicast
		 */
		bool is_multicast() const;

		/**
		 * Overload of the equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are equal, false otherwise
		 */
		bool operator==(const IPv6Address& rhs) const
		{
			return memcmp(to_bytes(), rhs.to_bytes(), sizeof(bytes_)) == 0;
		}

		/**
		 * Overload of the less-than operator
		 * @param[in] rhs The object to compare with
		 * @return True if the address value is lower than the other address value, false otherwise
		 */
		bool operator<(const IPv6Address& rhs) const
		{
			return memcmp(to_bytes(), rhs.to_bytes(), sizeof(bytes_)) < 0;
		}

		/**
		 * Overload of the not-equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are not equal, false otherwise
		 */
		bool operator!=(const IPv6Address& rhs) const
		{
			return !(*this == rhs);
		}

		/**
		 * Allocates a byte array and copies address value into it. Array deallocation is user responsibility
		 * @param[in] arr A pointer to where array will be allocated
		 * @param[out] length Returns the length in bytes of the array that was allocated
		 */
		void copy_to(uint8_t** arr, size_t& length) const;

		/**
		 * Gets a pointer to an already allocated byte array and copies the address value to it.
		 * This method assumes array allocated size is at least 16 (the size of an IPv6 address)
		 * @param[in] arr A pointer to the array which address will be copied to
		 */
		void copy_to(uint8_t* arr) const
		{
			memcpy(arr, bytes_.data(), bytes_.size() * sizeof(uint8_t));
		}

		// ---- Legacy upstream-style aliases (source compat; prefer the snake_case API above) ----
		VH_DEPRECATED("use to_bytes()")
		const uint8_t* toBytes() const { return to_bytes(); }
		VH_DEPRECATED("use to_string()")
		std::string toString() const { return to_string(); }
		VH_DEPRECATED("use copy_to()")
		void copyTo(uint8_t** arr, size_t& length) const { copy_to(arr, length); }
		VH_DEPRECATED("use copy_to()")
		void copyTo(uint8_t* arr) const { copy_to(arr); }

		/**
		 * Checks whether the address matches a network.
		 * @param network An IPv6Network network
		 * @return True if the address matches the network or false otherwise
		 */
		bool match_network(const IPv6Network& network) const;

		/**
		 * Checks whether the address matches a network.
		 * For example: this method will return true for address d6e5:83dc:0c58:bc5d:1449:5898:: and network
		 * which is one of:
		 * d6e5:83dc:0c58:bc5d::/64, d6e5:83dc:0c58:bc5d::/ffff:ffff:ffff:ffff::
		 * Another example: this method will return false for address d6e5:83dc:: and network which is one of:
		 * d6e5:83dc:0c58:bc5d::/64, d6e5:83dc:0c58:bc5d::/ffff:ffff:ffff:ffff::
		 * @param[in] network A string in one of these formats:
		 *  - IPV6_ADDRESS/Y where IPV6_ADDRESS is a valid IPv6 address and Y is a number between 0 and 128
		 *  - IPV6_ADDRESS/IPV6_NETMASK where IPV6_ADDRESS is a valid IPv6 address and IPV6_NETMASK is a valid
		 *    IPv6 netmask
		 * @return True if the address matches the network or false if it doesn't or if the network is invalid
		 */
		bool match_network(const std::string& network) const;

		/**
		 * A static method that checks whether a string represents a valid IPv6 address
		 * @param[in] addrAsString The std::string representation of the address
		 * @return True if the address is valid, false otherwise
		 */
		static bool is_valid_ipv6_address(const std::string& addrAsString);

		/**
		 * A static value representing a zero value of IPv6 address, meaning address of value
		 * "0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0".
		 */
		static const IPv6Address Zero;

		/**
		 * A static value representing the lower bound of IPv6 multicast ranges. The bound is inclusive.
		 * MulticastRangeLowerBound is initialized to "ff00:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0".
		 * In order to check whether the address is a multicast address the is_multicast method can be used.
		 */
		static const IPv6Address MulticastRangeLowerBound;

	private:
		std::array<uint8_t, 16> bytes_ = { 0 };
	};  // class IPv6Address

	/**
	 * @class IPAddress
	 * The class is a version-independent representation for an IP address
	 */
	class IPAddress
	{
	public:
		/**
		 * An enum representing the address type: IPv4 or IPv6
		 */
		enum AddressType
		{
			/**
			 * IPv4 address type
			 */
			IPv4AddressType,
			/**
			 * IPv6 address type
			 */
			IPv6AddressType
		};

		/**
		 * A default constructor that creates an instance of the class with unspecified IPv4 address
		 */
		IPAddress() : type_(IPv4AddressType)
		{}

		/**
		 * A constructor that creates an instance of the class out of IPv4Address.
		 * @param[in] addr A const reference to instance of IPv4Address
		 */
		IPAddress(const IPv4Address& addr) : type_(IPv4AddressType), ipv4_(addr)
		{}

		/**
		 * A constructor that creates an instance of the class out of IPv6Address.
		 * @param[in] addr A const reference to instance of IPv6Address
		 */
		IPAddress(const IPv6Address& addr) : type_(IPv6AddressType), ipv6_(addr)
		{}

		/**
		 * A constructor that creates an instance of the class out of std::string value
		 *
		 * @param[in] addrAsString The std::string representation of the address
		 * @throws std::invalid_argument The provided string does not represent a valid IPv4 or IPv6 address.
		 */
		IPAddress(const std::string& addrAsString);

		/**
		 * Overload of an assignment operator.
		 * @param[in] addr A const reference to instance of IPv4Address
		 * @return A reference to the assignee
		 */
		inline IPAddress& operator=(const IPv4Address& addr);

		/**
		 * Overload of an assignment operator.
		 * @param[in] addr A const reference to instance of IPv6Address
		 * @return A reference to the assignee
		 */
		inline IPAddress& operator=(const IPv6Address& addr);

		/**
		 * Gets the address type: IPv4 or IPv6
		 * @return The address type
		 */
		AddressType get_type() const
		{
			return static_cast<AddressType>(type_);
		}

		/**
		 * Returns a std::string representation of the address
		 * @return A string representation of the address
		 */
		std::string to_string() const
		{
			return (get_type() == IPv4AddressType) ? ipv4_.to_string() : ipv6_.to_string();
		}

		/**
		 * @return Determine whether the object contains an IP version 4 address
		 */
		bool is_ipv4() const
		{
			return get_type() == IPv4AddressType;
		}

		/**
		 * @return Determine whether the object contains an IP version 6 address
		 */
		bool is_ipv6() const
		{
			return get_type() == IPv6AddressType;
		}

		/**
		 * Determine whether the address is a multicast address
		 * @return True if an address is multicast
		 */
		bool is_multicast() const
		{
			return (get_type() == IPv4AddressType) ? ipv4_.is_multicast() : ipv6_.is_multicast();
		}

		/**
		 * Get a reference to IPv4 address instance
		 * @return The const reference to IPv4Address instance
		 */
		const IPv4Address& get_ipv4() const
		{
			return ipv4_;
		}

		/**
		 * Get a reference to IPv6 address instance
		 * @return The const reference to IPv6Address instance
		 */
		const IPv6Address& get_ipv6() const
		{
			return ipv6_;
		}

		// ---- Legacy upstream-style aliases (source compat; prefer the snake_case API above) ----
		VH_DEPRECATED("use get_type()")
		AddressType getType() const { return get_type(); }
		VH_DEPRECATED("use to_string()")
		std::string toString() const { return to_string(); }
		VH_DEPRECATED("use is_ipv4()")
		bool isIPv4() const { return is_ipv4(); }
		VH_DEPRECATED("use is_ipv6()")
		bool isIPv6() const { return is_ipv6(); }
		VH_DEPRECATED("use get_ipv4()")
		const IPv4Address& getIPv4() const { return get_ipv4(); }
		VH_DEPRECATED("use get_ipv6()")
		const IPv6Address& getIPv6() const { return get_ipv6(); }

		/**
		 * @return True if the address is zero, false otherwise
		 */
		bool is_zero() const
		{
			return (get_type() == IPv4AddressType) ? ipv4_ == IPv4Address::Zero : ipv6_ == IPv6Address::Zero;
		}

		/**
		 * Overload of the equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are equal, false otherwise
		 */
		inline bool operator==(const IPAddress& rhs) const;

		/**
		 * Overload of the less-than operator
		 * @param[in] rhs The object to compare with
		 * @return True if the address value is lower than the other address value, false otherwise
		 */
		inline bool operator<(const IPAddress& rhs) const;

		/**
		 * Overload of the not-equal-to operator
		 * @param[in] rhs The object to compare with
		 * @return True if the addresses are not equal, false otherwise
		 */
		bool operator!=(const IPAddress& rhs) const
		{
			return !(*this == rhs);
		}

	private:
		uint8_t type_;
		IPv4Address ipv4_;
		IPv6Address ipv6_;
	};

	// implementation of inline methods

	bool IPAddress::operator==(const IPAddress& rhs) const
	{
		if (is_ipv4())
			return rhs.is_ipv4() ? (ipv4_ == rhs.ipv4_) : false;

		return rhs.is_ipv6() ? ipv6_ == rhs.ipv6_ : false;
	}

	bool IPAddress::operator<(const IPAddress& rhs) const
	{
		if (is_ipv4())
		{
			// treat IPv4 as less than IPv6
			// If current obj is IPv4 and other is IPv6 return true
			return rhs.is_ipv4() ? (ipv4_ < rhs.ipv4_) : true;
		}
		return rhs.is_ipv6() ? ipv6_ < rhs.ipv6_ : false;
	}

	IPAddress& IPAddress::operator=(const IPv4Address& addr)
	{
		type_ = IPv4AddressType;
		ipv4_ = addr;
		return *this;
	}

	IPAddress& IPAddress::operator=(const IPv6Address& addr)
	{
		type_ = IPv6AddressType;
		ipv6_ = addr;
		return *this;
	}

	/**
	 * @class IPv4Network
	 * A class representing IPv4 network definition
	 */
	class IPv4Network
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of an address and a full prefix length,
		 * essentially making a network of consisting of only 1 address.
		 *
		 * @param address An address representing the network prefix.
		 */
		explicit IPv4Network(const IPv4Address& address) : IPv4Network(address, 32u)
		{}

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a prefix length
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param prefixLen A number between 0 and 32 representing the prefix length.
		 * @throws std::invalid_argument Prefix length is out of acceptable range.
		 */
		IPv4Network(const IPv4Address& address, uint8_t prefixLen);

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a netmask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param netmask A string representing a netmask in the format of X.X.X.X, for example: 255.255.0.0.
		 * Please notice that netmasks that start with zeros are invalid, for example: 0.0.255.255. The only netmask
		 * starting with zeros that is valid is 0.0.0.0.
		 * @throws std::invalid_argument The provided netmask is invalid.
		 */
		IPv4Network(const IPv4Address& address, const std::string& netmask);

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a netmask
		 * @param addressAndNetmask A string in one of these formats:
		 *  - X.X.X.X/Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y is a number between
		 *    0 and 32 representing the network prefix
		 *  - X.X.X.X/Y.Y.Y.Y where X.X.X.X is a valid IPv4 address representing the network prefix and Y.Y.Y.Y is
		 *    a valid netmask
		 * @throws std::invalid_argument The provided string does not represent a valid address and netmask format.
		 */
		IPv4Network(const std::string& addressAndNetmask);

		/**
		 * @return The prefix length, for example: the prefix length of 10.10.10.10/255.0.0.0 is 8
		 */
		uint8_t get_prefix_len() const;

		/**
		 * @return The netmask, for example: the netmask of 10.10.10.10/8 is 255.0.0.0
		 */
		std::string get_netmask() const
		{
			return IPv4Address(mask_).to_string();
		}

		/**
		 * @return The network prefix, for example: the network prefix of 10.10.10.10/16 is 10.10.0.0
		 */
		IPv4Address get_network_prefix() const
		{
			return IPv4Address(network_prefix_);
		}

		/**
		 * @return The lowest non-reserved IPv4 address in this network, for example: the lowest address
		 * in 10.10.10.10/16 is 10.10.0.1
		 */
		IPv4Address get_lowest_address() const;

		/**
		 * @return The highest non-reserved IPv4 address in this network, for example: the highest address
		 * in 10.10.10.10/16 is 10.10.255.254
		 */
		IPv4Address get_highest_address() const;

		/**
		 * @return The number of addresses in this network including reserved addresses, for example:
		 * the number of addresses in 10.10.0.0/24 is 256
		 */
		uint64_t get_total_address_count() const;

		/**
		 * @param address An IPv4 address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPv4Address& address) const;

		/**
		 * @param network An IPv4 network
		 * @return True is the input network is completely included within this network, false otherwise, for example:
		 * 10.10.10.10/16 includes 10.10.10.10/24 but doesn't include 10.10.10.10/8
		 */
		bool includes(const IPv4Network& network) const;

		/**
		 * @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		 * 192.168.0.0/16
		 */
		std::string to_string() const;

	private:
		uint32_t network_prefix_;
		uint32_t mask_;

		bool is_valid_netmask(const IPv4Address& netmaskAddress);
		void init_from_address_and_prefix_length(const IPv4Address& address, uint8_t prefixLen);
		void init_from_address_and_netmask(const IPv4Address& address, const IPv4Address& netmaskAddress);
	};

	/**
	 * @class IPv6Network
	 * A class representing IPv6 network definition
	 */
	class IPv6Network
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of an address and a full prefix length,
		 * essentially making a network of consisting of only 1 address.
		 *
		 * @param address An address representing the network prefix.
		 */
		explicit IPv6Network(const IPv6Address& address) : IPv6Network(address, 128u)
		{}

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a prefix length
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param prefixLen A number between 0 and 128 representing the prefix length.
		 * @throws std::invalid_argument Prefix length is out of acceptable range.
		 */
		IPv6Network(const IPv6Address& address, uint8_t prefixLen);

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a netmask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param netmask A string representing a netmask in valid IPv6 format, for example: ffff:ffff::.
		 * Please notice that netmasks that start with zeros are invalid, for example: 0:ffff::. The only netmask
		 * starting with zeros that is valid is all zeros (::).
		 * @throws std::invalid_argument The provided netmask is invalid.
		 */
		IPv6Network(const IPv6Address& address, const std::string& netmask);

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a netmask
		 * @param addressAndNetmask A string in one of these formats:
		 *  - IPV6_ADDRESS/Y where IPV6_ADDRESS is a valid IPv6 address representing the network prefix and Y is
		 *    a number between 0 and 128 representing the network prefix
		 *  - IPV6_ADDRESS/IPV6_NETMASK where IPV6_ADDRESS is a valid IPv6 address representing the network prefix
		 *    and IPV6_NETMASK is a valid IPv6 netmask
		 * @throws std::invalid_argument The provided string does not represent a valid address and netmask format.
		 */
		IPv6Network(const std::string& addressAndNetmask);

		/**
		 * @return The prefix length, for example: the prefix length of 3546::/ffff:: is 16
		 */
		uint8_t get_prefix_len() const;

		/**
		 * @return The netmask, for example: the netmask of 3546::/16 is ffff::
		 */
		std::string get_netmask() const
		{
			return IPv6Address(mask_).to_string();
		}

		/**
		 * @return The network prefix, for example: the network prefix of 3546:f321::/16 is 3546::
		 */
		IPv6Address get_network_prefix() const
		{
			return IPv6Address(network_prefix_);
		}

		/**
		 * @return The lowest non-reserved IPv6 address in this network, for example: the lowest address in 3546::/16 is
		 * 3546::1
		 */
		IPv6Address get_lowest_address() const;

		/**
		 * @return The highest IPv6 address in this network, for example: the highest address in 3546::/16 is
		 * 3546:ffff:ffff:ffff:ffff:ffff:ffff:ffff
		 */
		IPv6Address get_highest_address() const;

		/**
		 * @return The number of addresses in this network, for example: the number of addresses in 16ff::/120 is 256.
		 * If the number of addresses exceeds the size of uint64_t a std::out_of_range exception is thrown
		 */
		uint64_t get_total_address_count() const;

		/**
		 * @param address An IPv6 address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPv6Address& address) const;

		/**
		 * @param network An IPv6 network
		 * @return True is the input network is completely included within this network, false otherwise, for example:
		 * 3546::/64 includes 3546::/120 but doesn't include 3546::/16
		 */
		bool includes(const IPv6Network& network) const;

		/**
		 * @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		 * fda7:9f81:6c23:275::/64
		 */
		std::string to_string() const;

	private:
		uint8_t network_prefix_[16];
		uint8_t mask_[16];

		bool is_valid_netmask(const IPv6Address& netmaskAddress);
		void init_from_address_and_prefix_length(const IPv6Address& address, uint8_t prefixLen);
		void init_from_address_and_netmask(const IPv6Address& address, const IPv6Address& netmaskAddress);
	};

	/**
	 * @class IPNetwork
	 * A class representing version independent IP network definition, both IPv4 and IPv6 are included
	 */
	class IPNetwork
	{
	public:
		/**
		 * A constructor that creates an instance of the class out of an IP address and a full prefix length,
		 * essentially making a network of consisting of only 1 address.
		 *
		 * @param address An address representing the network prefix.
		 */
		explicit IPNetwork(const IPAddress& address) : IPNetwork(address, address.is_ipv4() ? 32u : 128u)
		{}

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a prefix length
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param prefixLen A number representing the prefix length. Allowed ranges are 0 - 32 for IPv4 networks and 0 -
		 * 128 for IPv6 networks.
		 * @throws std::invalid_argument Prefix length is out of acceptable range.
		 */
		IPNetwork(const IPAddress& address, uint8_t prefixLen)
		{
			if (address.is_ipv4())
			{
				ipv4_network_ = std::unique_ptr<IPv4Network>(new IPv4Network(address.get_ipv4(), prefixLen));
			}
			else
			{
				ipv6_network_ = std::unique_ptr<IPv6Network>(new IPv6Network(address.get_ipv6(), prefixLen));
			}
		}

		/**
		 * A constructor that creates an instance of the class out of an address representing the network prefix
		 * and a netmask
		 * @param address An address representing the network prefix. If the address is invalid std::invalid_argument
		 * exception is thrown
		 * @param netmask A string representing a netmask in valid format, for example: ffff:ffff:: for IPv6 networks
		 * or 255.255.0.0 for IPv4 networks.
		 * Please notice that netmasks that start with zeros are invalid, for example: 0:ffff:: or 0.255.255.255.
		 * The only netmask starting with zeros that is valid is all zeros (:: or 0.0.0.0).
		 * @throws std::invalid_argument The provided netmask is invalid.
		 */
		IPNetwork(const IPAddress& address, const std::string& netmask)
		{
			if (address.is_ipv4())
			{
				ipv4_network_ = std::unique_ptr<IPv4Network>(new IPv4Network(address.get_ipv4(), netmask));
			}
			else
			{
				ipv6_network_ = std::unique_ptr<IPv6Network>(new IPv6Network(address.get_ipv6(), netmask));
			}
		}

		/**
		 * A constructor that creates an instance of the class out of a string representing the network prefix and
		 * a prefix length or a netmask
		 * @param addressAndNetmask A string in one of these formats:
		 *  - IP_ADDRESS/Y where IP_ADDRESS is a valid IP address representing the network prefix and Y is
		 *    a number representing the network prefix
		 *  - IP_ADDRESS/NETMASK where IP_ADDRESS is a valid IP address representing the network prefix and NETMASK
		 *    is a valid netmask for this type of network (IPv4 or IPv6 network)
		 * @throws std::invalid_argument The provided string does not represent a valid address and netmask format.
		 */
		IPNetwork(const std::string& addressAndNetmask)
		{
			try
			{
				ipv4_network_ = std::unique_ptr<IPv4Network>(new IPv4Network(addressAndNetmask));
			}
			catch (const std::invalid_argument&)
			{
				ipv6_network_ = std::unique_ptr<IPv6Network>(new IPv6Network(addressAndNetmask));
			}
		}

		/**
		 * A copy c'tor for this class
		 * @param other The instance to copy from
		 */
		IPNetwork(const IPNetwork& other)
		{
			if (other.ipv4_network_)
			{
				ipv4_network_ = std::unique_ptr<IPv4Network>(new IPv4Network(*other.ipv4_network_));
			}

			if (other.ipv6_network_)
			{
				ipv6_network_ = std::unique_ptr<IPv6Network>(new IPv6Network(*other.ipv6_network_));
			}
		}

		/**
		 * Overload of an assignment operator.
		 * @param[in] other An instance of IPNetwork to assign
		 * @return A reference to the assignee
		 */
		IPNetwork& operator=(const IPNetwork& other)
		{
			if (other.is_ipv4_network())
			{
				return this->operator=(*other.ipv4_network_);
			}
			else
			{
				return this->operator=(*other.ipv6_network_);
			}
		}

		/**
		 * Overload of an assignment operator.
		 * @param[in] other An instance of IPv4Network to assign
		 * @return A reference to the assignee
		 */
		IPNetwork& operator=(const IPv4Network& other)
		{
			if (ipv4_network_)
			{
				ipv4_network_ = nullptr;
			}

			if (ipv6_network_)
			{
				ipv6_network_ = nullptr;
			}

			ipv4_network_ = std::unique_ptr<IPv4Network>(new IPv4Network(other));

			return *this;
		}

		/**
		 * Overload of an assignment operator.
		 * @param[in] other An instance of IPv6Network to assign
		 * @return A reference to the assignee
		 */
		IPNetwork& operator=(const IPv6Network& other)
		{
			if (ipv4_network_)
			{
				ipv4_network_ = nullptr;
			}

			if (ipv6_network_)
			{
				ipv6_network_ = nullptr;
			}

			ipv6_network_ = std::unique_ptr<IPv6Network>(new IPv6Network(other));

			return *this;
		}

		/**
		 * @return The prefix length, for example: the prefix length of 3546::/ffff:: is 16, the prefix length of
		 * 10.10.10.10/255.0.0.0 is 8
		 */
		uint8_t get_prefix_len() const
		{
			return (ipv4_network_ != nullptr ? ipv4_network_->get_prefix_len() : ipv6_network_->get_prefix_len());
		}

		/**
		 * @return The netmask, for example: the netmask of 3546::/16 is ffff::, the netmask of 10.10.10.10/8 is
		 * 255.0.0.0
		 */
		std::string get_netmask() const
		{
			return (ipv4_network_ != nullptr ? ipv4_network_->get_netmask() : ipv6_network_->get_netmask());
		}

		/**
		 * @return The network prefix, for example: the network prefix of 3546:f321::/16 is 3546::, the network prefix
		 * of 10.10.10.10/16 is 10.10.0.0
		 */
		IPAddress get_network_prefix() const
		{
			return (ipv4_network_ != nullptr ? IPAddress(ipv4_network_->get_network_prefix())
			                                 : IPAddress(ipv6_network_->get_network_prefix()));
		}

		/**
		 * @return The lowest non-reserved IP address in this network, for example: the lowest address in 3546::/16 is
		 * 3546::1, the lowest address in 10.10.10.10/16 is 10.10.0.1
		 */
		IPAddress get_lowest_address() const
		{
			return (ipv4_network_ != nullptr ? IPAddress(ipv4_network_->get_lowest_address())
			                                 : IPAddress(ipv6_network_->get_lowest_address()));
		}

		/**
		 * @return The highest non-reserved IP address in this network, for example: the highest address in 3546::/16 is
		 * 3546:ffff:ffff:ffff:ffff:ffff:ffff:ffff, the highest address in 10.10.10.10/16 is 10.10.255.254
		 */
		IPAddress get_highest_address() const
		{
			return (ipv4_network_ != nullptr ? IPAddress(ipv4_network_->get_highest_address())
			                                 : IPAddress(ipv6_network_->get_highest_address()));
		}

		/**
		 * @return The number of addresses in this network, for example: the number of addresses in 16ff::/120 is 256,
		 * the number of addresses in 10.10.0.0/24 is 256. If the number of addresses exceeds the size of uint64_t
		 * a std::out_of_range exception is thrown
		 */
		uint64_t get_total_address_count() const
		{
			return (ipv4_network_ != nullptr ? ipv4_network_->get_total_address_count()
			                                 : ipv6_network_->get_total_address_count());
		}

		/**
		 * @return True if this is an IPv4 network, false otherwise
		 */
		bool is_ipv4_network() const
		{
			return ipv4_network_ != nullptr;
		}

		/**
		 * @return True if this is an IPv6 network, false otherwise
		 */
		bool is_ipv6_network() const
		{
			return ipv6_network_ != nullptr;
		}

		/**
		 * @param address An IP address
		 * @return True is the address belongs to the network, false otherwise or if the address isn't valid
		 */
		bool includes(const IPAddress& address) const
		{
			if (ipv4_network_ != nullptr)
			{
				if (address.is_ipv6())
				{
					return false;
				}

				return ipv4_network_->includes(address.get_ipv4());
			}
			else
			{
				if (address.is_ipv4())
				{
					return false;
				}

				return ipv6_network_->includes(address.get_ipv6());
			}
		}

		/**
		 * @param network An IP network
		 * @return True is the input network is completely included within this network, false otherwise
		 */
		bool includes(const IPNetwork& network) const
		{
			if (ipv4_network_ != nullptr)
			{
				if (network.is_ipv6_network())
				{
					return false;
				}

				return ipv4_network_->includes(*network.ipv4_network_);
			}
			else
			{
				if (network.is_ipv4_network())
				{
					return false;
				}

				return ipv6_network_->includes(*network.ipv6_network_);
			}
		}

		/**
		 * @return A string representation of the network in a format of NETWORK_PREFIX/PREFIX_LEN, for example:
		 * fda7:9f81:6c23:275::/64 or 192.168.0.0/16
		 */
		std::string to_string() const
		{
			return (ipv4_network_ != nullptr ? ipv4_network_->to_string() : ipv6_network_->to_string());
		}

	private:
		std::unique_ptr<IPv4Network> ipv4_network_;
		std::unique_ptr<IPv6Network> ipv6_network_;
	};
}  // namespace vanhooks::net

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::IPv4Address& ipv4Address)
{
	os << ipv4Address.to_string();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::IPv6Address& ipv6Address)
{
	os << ipv6Address.to_string();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::IPAddress& ipAddress)
{
	os << ipAddress.to_string();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::IPv4Network& network)
{
	os << network.to_string();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::IPv6Network& network)
{
	os << network.to_string();
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::IPNetwork& network)
{
	os << network.to_string();
	return os;
}
// ---- end IpAddress.h ----

// ---- begin IpAddressUtils.h ----
/// @file

// Forward declarations
struct in_addr;
struct in6_addr;

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	// Forward declarations
	class IPv4Address;
	class IPv6Address;
	class IPAddress;

	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	bool operator==(const IPv4Address& lhs, const in_addr& rhs);
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const IPv4Address& lhs, const in_addr& rhs)
	{
		return !(lhs == rhs);
	}
	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	inline bool operator==(const in_addr& lhs, const IPv4Address& rhs)
	{
		return rhs == lhs;
	}
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const in_addr& lhs, const IPv4Address& rhs)
	{
		return !(lhs == rhs);
	}

	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	bool operator==(const IPv6Address& lhs, const in6_addr& rhs);
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const IPv6Address& lhs, const in6_addr& rhs)
	{
		return !(lhs == rhs);
	}
	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	inline bool operator==(const in6_addr& lhs, const IPv6Address& rhs)
	{
		return rhs == lhs;
	}
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const in6_addr& lhs, const IPv6Address& rhs)
	{
		return !(lhs == rhs);
	}

	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	bool operator==(const IPAddress& lhs, const in_addr& rhs);
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const IPAddress& lhs, const in_addr& rhs)
	{
		return !(lhs == rhs);
	}
	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	inline bool operator==(const in_addr& lhs, const IPAddress& rhs)
	{
		return rhs == lhs;
	}
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const in_addr& lhs, const IPAddress& rhs)
	{
		return !(lhs == rhs);
	}

	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	bool operator==(const IPAddress& lhs, const in6_addr& rhs);
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const IPAddress& lhs, const in6_addr& rhs)
	{
		return !(lhs == rhs);
	}
	/**
	 * Overload of the equal-to operator
	 * @return True if the addresses are equal, false otherwise
	 */
	inline bool operator==(const in6_addr& lhs, const IPAddress& rhs)
	{
		return rhs == lhs;
	}
	/**
	 * Overload of the not-equal-to operator
	 * @return True if the addresses differ, false otherwise
	 */
	inline bool operator!=(const in6_addr& lhs, const IPAddress& rhs)
	{
		return !(lhs == rhs);
	}
}  // namespace vanhooks::net
// ---- end IpAddressUtils.h ----

// ---- begin IpUtils.h ----
#include <stdint.h>
#ifdef __linux__
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif
#if defined(__APPLE__)
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif
#if defined(_WIN32)
#	include <ws2tcpip.h>
#endif
#if defined(__FreeBSD__)
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#endif

/// @file

// Both Visual C++ Compiler and MinGW-w64 define inet_ntop() and inet_pton()
// Add compatibility functions for old MinGW (aka MinGW32)
// We use "__MINGW64_VERSION_MAJOR" and not __MINGW64__ to detect MinGW-w64 compiler
// because the second one is not defined for MinGW-w64 in 32bits mode
#if defined(_WIN32) && !defined(_MSC_VER) && (!defined(__MINGW64_VERSION_MAJOR) || (__MINGW64_VERSION_MAJOR < 8))
/**
 * Convert a network format address to presentation format.
 * @param[in] af Address family, can be either AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param[in] src Network address structure, can be either in_addr (IPv4) or in6_addr (IPv6)
 * @param[out] dst Network address string representation
 * @param[in] size 'dst' Maximum size
 * @return pointer to presentation format address ('dst'), or nullptr (see errno).
 */
const char* inet_ntop(int af, const void* src, char* dst, size_t size);

/**
 * Convert from presentation format (which usually means ASCII printable)
 * to network format (which is usually some kind of binary format).
 * @param[in] af Address family, can be either AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param[in] src Network address string representation
 * @param[out] dst Network address structure result, can be either in_addr (IPv4) or in6_addr (IPv6)
 * @return
 * 1 if the address was valid for the specified address family;
 * 0 if the address wasn't valid ('dst' is untouched in this case);
 * -1 if some other error occurred ('dst' is untouched in this case, too)
 */
int inet_pton(int af, const char* src, void* dst);
#endif

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	namespace internal
	{
		/**
		 * Extract IPv4 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Address in in_addr format
		 * @throws std::invalid_argument Sockaddr family is not AF_INET or sockaddr is nullptr.
		 */
		in_addr* sockaddr2in_addr(sockaddr* sa);

		/**
		 * Attempt to extract IPv4 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Pointer to address in in_addr format or nullptr if extraction fails.
		 */
		in_addr* try_sockaddr2in_addr(sockaddr* sa);

		/**
		 * Extract IPv6 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Address in in6_addr format
		 * @throws std::invalid_argument Sockaddr family is not AF_INET6 or sockaddr is nullptr.
		 */
		in6_addr* sockaddr2in6_addr(sockaddr* sa);

		/**
		 * Attempt to extract IPv6 address from sockaddr
		 * @param[in] sa - input sockaddr
		 * @return Pointer to address in in6_addr format or nullptr if extraction fails.
		 */
		in6_addr* try_sockaddr2in6_addr(sockaddr* sa);

		/**
		 * Converts a sockaddr format address to its string representation
		 * @param[in] sa Address in sockaddr format
		 * @param[out] resultString String representation of the address
		 * @param[in] resultBufLen Length of the result buffer.
		 * @throws std::invalid_argument Sockaddr family is not AF_INET or AF_INET6, sockaddr is nullptr or the result
		 * str buffer is insufficient.
		 */
		void sockaddr2string(sockaddr const* sa, char* resultString, size_t resultBufLen);

		/**
		 * Convert a in_addr format address to 32bit representation
		 * @param[in] inAddr Address in in_addr format
		 * @return Address in 32bit format
		 */
		uint32_t in_addr2int(in_addr inAddr);
	}  // namespace internal
}  // namespace vanhooks::net
// ---- end IpUtils.h ----

// ---- begin GeneralUtils.h ----
#include <string>
#include <stdint.h>
#include <type_traits>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * Convert a byte array into a string of hex characters. For example: for the array { 0xaa, 0x2b, 0x10 } the string
	 * "aa2b10" will be returned
	 * @param[in] byteArr A byte array
	 * @param[in] byteArrSize The size of the byte array [in bytes]
	 * @param[in] stringSizeLimit An optional parameter that enables to limit the returned string size. If set to a
	 * positive integer value the returned string size will be equal or less than this value. If the string
	 * representation of the whole array is longer than this size then only part of the array will be read. The default
	 * value is -1 which means no string size limitation
	 * @return A string of hex characters representing the byte array
	 */
	std::string byte_array_to_hex_string(const uint8_t* byteArr, size_t byteArrSize, int stringSizeLimit = -1);

	/**
	 * Convert a string of hex characters into a byte array. For example: for the string "aa2b10" an array of values
	 * { 0xaa, 0x2b, 0x10 } will be returned
	 * @param[in] hexString A string of hex characters
	 * @param[out] resultByteArr A pre-allocated byte array where the result will be written to
	 * @param[in] resultByteArrSize The size of the pre-allocated byte array
	 * @return The size of the result array. If the string represents an array that is longer than the pre-allocated
	 * size (resultByteArrSize) then the result array will contain only the part of the string that managed to fit into
	 * the array, and the returned size will be resultByteArrSize. However if the string represents an array that is
	 * shorter than the pre-allocated size then some of the cells will remain empty and contain zeros, and the returned
	 * size will be the part of the array that contain data. If the input is an illegal hex string 0 will be returned.
	 * Illegal hex string means odd number of characters or a string that contains non-hex characters
	 */
	size_t hex_string_to_byte_array(const std::string& hexString, uint8_t* resultByteArr, size_t resultByteArrSize);

	VH_DEPRECATED("use byte_array_to_hex_string()")
	inline std::string byteArrayToHexString(const uint8_t* byteArr, size_t byteArrSize, int stringSizeLimit = -1)
	{
		return byte_array_to_hex_string(byteArr, byteArrSize, stringSizeLimit);
	}

	VH_DEPRECATED("use hex_string_to_byte_array()")
	inline size_t hexStringToByteArray(const std::string& hexString, uint8_t* resultByteArr, size_t resultByteArrSize)
	{
		return hex_string_to_byte_array(hexString, resultByteArr, resultByteArrSize);
	}

	/**
	 * This is a cross platform version of memmem (https://man7.org/linux/man-pages/man3/memmem.3.html) which is not
	 * supported on all platforms.
	 * @param[in] haystack A pointer to the buffer to be searched
	 * @param[in] haystackLen Length of the haystack buffer
	 * @param[in] needle A pointer to a buffer that will be searched for
	 * @param[in] needleLen Length of the needle buffer
	 * @return A pointer to the beginning of the substring, or nullptr if the substring is not found
	 */
	char* cross_platform_memmem(const char* haystack, size_t haystackLen, const char* needle, size_t needleLen);

	/**
	 * Calculates alignment.
	 * @param[in] number Given number
	 * @return The aligned number
	 */
	template <int alignment> static int align(int number)
	{
		// Only works for alignment with power of 2
		constexpr bool isPowerOfTwo = alignment && ((alignment & (alignment - 1)) == 0);
		static_assert(isPowerOfTwo, "Alignment must be a power of 2");
		int mask = alignment - 1;
		return (number + mask) & ~mask;
	}

	/**
	 * A template class to calculate enum class hash
	 * @tparam EnumClass
	 */
	template <typename EnumClass, typename std::enable_if<std::is_enum<EnumClass>::value, bool>::type = false>
	struct EnumClassHash
	{
		size_t operator()(EnumClass value) const
		{
			return static_cast<typename std::underlying_type<EnumClass>::type>(value);
		}
	};
}  // namespace vanhooks::net
// ---- end GeneralUtils.h ----

// ---- begin SystemUtils.h ----
#include <stdint.h>
#include <string>
#include <vector>

/// @file

#define MAX_NUM_OF_CORES 32

#ifdef _MSC_VER
int gettimeofday(struct timeval* tp, struct timezone* tzp);
#endif

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct SystemCore
	 * Represents data of 1 CPU core. Current implementation supports up to 32 cores
	 */
	struct SystemCore
	{
		/**
		 * Core position in a 32-bit mask. For each core this attribute holds a 4B integer where only 1 bit is set,
		 * according to the core ID. For example:
		 * - In core #0 the right-most bit will be set (meaning the number 0x01);
		 * - in core #5 the 5th right-most bit will be set (meaning the number 0x20)
		 */
		uint32_t Mask;

		/**
		 * Core ID - a value between 0 and 31
		 */
		uint8_t Id;

		/**
		 * Overload of the comparison operator
		 * @return true if 2 addresses are equal. False otherwise
		 */
		bool operator==(const SystemCore& other) const
		{
			return Id == other.Id;
		}
	};

	/**
	 * @struct SystemCores
	 * Contains static representation to all 32 cores and a static array to map core ID (integer) to a SystemCore struct
	 */
	struct SystemCores
	{
		/**
		 * Static representation of core #0
		 */
		static const SystemCore Core0;
		/**
		 * Static representation of core #1
		 */
		static const SystemCore Core1;
		/**
		 * Static representation of core #2
		 */
		static const SystemCore Core2;
		/**
		 * Static representation of core #3
		 */
		static const SystemCore Core3;
		/**
		 * Static representation of core #4
		 */
		static const SystemCore Core4;
		/**
		 * Static representation of core #5
		 */
		static const SystemCore Core5;
		/**
		 * Static representation of core #6
		 */
		static const SystemCore Core6;
		/**
		 * Static representation of core #7
		 */
		static const SystemCore Core7;
		/**
		 * Static representation of core #8
		 */
		static const SystemCore Core8;
		/**
		 * Static representation of core #9
		 */
		static const SystemCore Core9;
		/**
		 * Static representation of core #10
		 */
		static const SystemCore Core10;
		/**
		 * Static representation of core #11
		 */
		static const SystemCore Core11;
		/**
		 * Static representation of core #12
		 */
		static const SystemCore Core12;
		/**
		 * Static representation of core #13
		 */
		static const SystemCore Core13;
		/**
		 * Static representation of core #14
		 */
		static const SystemCore Core14;
		/**
		 * Static representation of core #15
		 */
		static const SystemCore Core15;
		/**
		 * Static representation of core #16
		 */
		static const SystemCore Core16;
		/**
		 * Static representation of core #17
		 */
		static const SystemCore Core17;
		/**
		 * Static representation of core #18
		 */
		static const SystemCore Core18;
		/**
		 * Static representation of core #19
		 */
		static const SystemCore Core19;
		/**
		 * Static representation of core #20
		 */
		static const SystemCore Core20;
		/**
		 * Static representation of core #21
		 */
		static const SystemCore Core21;
		/**
		 * Static representation of core #22
		 */
		static const SystemCore Core22;
		/**
		 * Static representation of core #23
		 */
		static const SystemCore Core23;
		/**
		 * Static representation of core #24
		 */
		static const SystemCore Core24;
		/**
		 * Static representation of core #25
		 */
		static const SystemCore Core25;
		/**
		 * Static representation of core #26
		 */
		static const SystemCore Core26;
		/**
		 * Static representation of core #27
		 */
		static const SystemCore Core27;
		/**
		 * Static representation of core #28
		 */
		static const SystemCore Core28;
		/**
		 * Static representation of core #29
		 */
		static const SystemCore Core29;
		/**
		 * Static representation of core #30
		 */
		static const SystemCore Core30;
		/**
		 * Static representation of core #31
		 */
		static const SystemCore Core31;

		/**
		 * A static array for mapping core ID (integer) to the corresponding static SystemCore representation
		 */
		static const SystemCore IdToSystemCore[MAX_NUM_OF_CORES];
	};

	typedef uint32_t CoreMask;

	/**
	 * Get total number of cores on device
	 * @return Total number of CPU cores on device
	 */
	int get_num_of_cores();

	/**
	 * Create a core mask for all cores available on machine
	 * @return A core mask for all cores available on machine
	 */
	CoreMask get_core_mask_for_all_machine_cores();

	/**
	 * Create a core mask from a vector of system cores
	 * @param[in] cores A vector of SystemCore instances
	 * @return A core mask representing these cores
	 */
	CoreMask create_core_mask_from_core_vector(const std::vector<SystemCore>& cores);

	/**
	 * Create a core mask from a vector of core IDs
	 * @param[in] coreIds A vector of core IDs
	 * @return A core mask representing these cores
	 */
	CoreMask create_core_mask_from_core_ids(const std::vector<int>& coreIds);

	/**
	 * Convert a core mask into a vector of its appropriate system cores
	 * @param[in] coreMask The input core mask
	 * @param[out] resultVec The vector that will contain the system cores
	 */
	void create_core_vector_from_core_mask(CoreMask coreMask, std::vector<SystemCore>& resultVec);

	/**
	 * Execute a shell command and return its output
	 * @param[in] command The command to run
	 * @return The output of the command (both stdout and stderr)
	 * @throws std::runtime_error Error executing the command.
	 */
	std::string execute_shell_command(const std::string& command);

	/**
	 * Check if a directory exists
	 * @param[in] dirPath Full path of the directory to search
	 * @return True if directory exists, false otherwise
	 */
	bool directory_exists(const std::string& dirPath);

	/**
	 * Retrieve a system-wide real-time accurate clock. It's actually a multi-platform version of clock_gettime() which
	 * is fully supported only on Linux
	 * @param[out] sec The second portion of the time
	 * @param[out] nsec The nanosecond portion of the time
	 * @return 0 for success, or -1 for failure
	 */
	int clock_get_time(long& sec, long& nsec);

	/**
	 * A multi-platform version of the popular sleep method. This method simply runs the right sleep method, according
	 * to the platform it is running on.
	 * @param[in] seconds Number of seconds to sleep
	 */
	void multi_platform_sleep(uint32_t seconds);

	/**
	 * A multi-platform version of sleep in milliseconds resolution. This method simply runs the right sleep method,
	 * according to the platform it is running on.
	 * @param[in] milliseconds Number of milliseconds to sleep
	 */
	void multi_platform_m_sleep(uint32_t milliseconds);

	/**
	 * A multi-platform version of `htons` which convert host to network byte order
	 * @param[in] host Value in host byte order
	 * @return Value in network byte order
	 */
	uint16_t host_to_net16(uint16_t host);

	/**
	 * A multi-platform version of `ntohs` which convert network to host byte order
	 * @param[in] net Value in network byte order
	 * @return Value in host byte order
	 */
	uint16_t net_to_host16(uint16_t net);

	/**
	 * A multi-platform version of `htonl` which convert host to network byte order
	 * @param[in] host Value in host byte order
	 * @return Value in network byte order
	 */
	uint32_t host_to_net32(uint32_t host);

	/**
	 * A multi-platform version of `ntohl` which convert network to host byte order
	 * @param[in] net Value in network byte order
	 * @return Value in host byte order
	 */
	uint32_t net_to_host32(uint32_t net);

	VH_DEPRECATED("use host_to_net16()")
	inline uint16_t hostToNet16(uint16_t host) { return host_to_net16(host); }
	VH_DEPRECATED("use net_to_host16()")
	inline uint16_t netToHost16(uint16_t net) { return net_to_host16(net); }
	VH_DEPRECATED("use host_to_net32()")
	inline uint32_t hostToNet32(uint32_t host) { return host_to_net32(host); }
	VH_DEPRECATED("use net_to_host32()")
	inline uint32_t netToHost32(uint32_t net) { return net_to_host32(net); }

	/**
	 * @class AppName
	 * This class extracts the application name from the current running executable and stores it for usage of the
	 * application throughout its runtime. This class should be initialized once in the beginning of the main() method
	 * using AppName#init() and from then on the app name could be retrieved using AppName#get()
	 */
	class AppName
	{
	private:
		static std::string app_name_;

	public:
		/**
		 * Static init method which should be called once at the beginning of the main method.
		 * @param[in] argc The argc param from main()
		 * @param[in] argv The argv param from main()
		 */
		// cppcheck-suppress constParameter
		static void init(int argc, char* argv[])
		{
			if (argc == 0)
			{
				app_name_.clear();
				return;
			}

			app_name_ = argv[0];

			// remove Linux/Unix path
			size_t lastPos = app_name_.rfind('/');
			if (lastPos != std::string::npos)
			{
				app_name_ = app_name_.substr(lastPos + 1);
			}

			// remove Windows path
			lastPos = app_name_.rfind('\\');
			if (lastPos != std::string::npos)
			{
				app_name_ = app_name_.substr(lastPos + 1);
			}

			// remove file extension
			lastPos = app_name_.rfind('.');
			if (lastPos != std::string::npos)
			{
				app_name_.resize(lastPos);
			}
		}

		/**
		 * @return The app name as extracted from the current running executable
		 */
		static const std::string& get()
		{
			return app_name_;
		}
	};

	/**
	 * @class ApplicationEventHandler
	 * A singleton class that provides callbacks for events that occur during application life-cycle such as ctrl+c
	 * pressed, application closed, killed, etc.
	 */
	class ApplicationEventHandler
	{
	public:
		/**
		 * @typedef EventHandlerCallback
		 * The callback to be invoked when the event occurs
		 * @param[in] cookie A pointer the the cookie provided by the user in ApplicationEventHandler c'tor
		 */
		typedef void (*EventHandlerCallback)(void* cookie);

		/**
		 * As ApplicationEventHandler is a singleton, this is the static getter to retrieve its instance
		 * @return The singleton instance of ApplicationEventHandler
		 */
		static ApplicationEventHandler& get_instance()
		{
			static ApplicationEventHandler instance;
			return instance;
		}

		/**
		 * Register for an application-interrupted event, meaning ctrl+c was pressed
		 * @param[in] handler The callback to be activated when the event occurs
		 * @param[in] cookie A pointer to a user provided object. This object will be transferred to the
		 * EventHandlerCallback callback. This cookie is very useful for transferring objects that give context to the
		 * event callback
		 */
		void on_application_interrupted(EventHandlerCallback handler, void* cookie);

	private:
		EventHandlerCallback application_interrupted_handler_;
		void* application_interrupted_cookie_;

		// private c'tor
		ApplicationEventHandler();

#if defined(_WIN32)
		static int handler_routine(unsigned long fdwCtrlType);
#else
		static void handler_routine(int signum);
#endif
	};

}  // namespace vanhooks::net
// ---- end SystemUtils.h ----

// ---- begin Logger.h ----
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdint.h>

#ifndef LOG_MODULE
#	define LOG_MODULE UndefinedLogModule
#endif

// Use __FILE_NAME__ to avoid leaking complete full path
#ifdef __FILE_NAME__
#	define VH_FILENAME __FILE_NAME__
#else
#	define VH_FILENAME __FILE__
#endif

#define VH_LOG(level, message)                                                                                       \
	do                                                                                                                 \
	{                                                                                                                  \
		std::ostringstream* sstream = vanhooks::net::Logger::get_instance().internal_create_log_stream();                           \
		(*sstream) << message;                                                                                         \
		vanhooks::net::Logger::get_instance().internal_print_log_message(sstream, level, VH_FILENAME, __FUNCTION__, __LINE__);  \
	} while (0)

#define VH_LOG_DEBUG(message)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		if (vanhooks::net::Logger::get_instance().logs_enabled() && vanhooks::net::Logger::get_instance().is_debug_enabled(LOG_MODULE))       \
		{                                                                                                              \
			VH_LOG(vanhooks::net::Logger::Debug, message);                                                                    \
		}                                                                                                              \
	} while (0)

#define VH_LOG_ERROR(message)                                                                                        \
	do                                                                                                                 \
	{                                                                                                                  \
		VH_LOG(vanhooks::net::Logger::Error, message);                                                                        \
	} while (0)

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * An enum representing all VanHooks modules
	 */
	enum LogModule
	{
		UndefinedLogModule,
		CommonLogModuleIpUtils,          ///< IP Utils module (Common++)
		CommonLogModuleTablePrinter,     ///< Table printer module (Common++)
		CommonLogModuleGenericUtils,     ///< Generic Utils (Common++)
		PacketLogModuleRawPacket,        ///< RawPacket module (Packet++)
		PacketLogModulePacket,           ///< Packet module (Packet++)
		PacketLogModuleLayer,            ///< Layer module (Packet++)
		PacketLogModuleAsn1Codec,        ///< Asn1Codec module (Packet++)
		PacketLogModuleArpLayer,         ///< ArpLayer module (Packet++)
		PacketLogModuleEthLayer,         ///< EthLayer module (Packet++)
		PacketLogModuleIPv4Layer,        ///< IPv4Layer module (Packet++)
		PacketLogModuleIPv6Layer,        ///< IPv6Layer module (Packet++)
		PacketLogModulePayloadLayer,     ///< PayloadLayer module (Packet++)
		PacketLogModuleTcpLayer,         ///< TcpLayer module (Packet++)
		PacketLogModuleUdpLayer,         ///< UdpLayer module (Packet++)
		PacketLogModuleVlanLayer,        ///< VlanLayer module (Packet++)
		PacketLogModuleHttpLayer,        ///< HttpLayer module (Packet++)
		PacketLogModulePPPoELayer,       ///< PPPoELayer module (Packet++)
		PacketLogModuleDnsLayer,         ///< DnsLayer module (Packet++)
		PacketLogModuleMplsLayer,        ///< MplsLayer module (Packet++)
		PacketLogModuleIcmpLayer,        ///< IcmpLayer module (Packet++)
		PacketLogModuleIcmpV6Layer,      ///< IcmpV6Layer module (Packet++)
		PacketLogModuleGreLayer,         ///< GreLayer module (Packet++)
		PacketLogModuleSSLLayer,         ///< SSLLayer module (Packet++)
		PacketLogModuleSllLayer,         ///< SllLayer module (Packet++)
		PacketLogModuleNflogLayer,       ///< NflogLayer module (Packet++)
		PacketLogModuleDhcpLayer,        ///< DhcpLayer module (Packet++)
		PacketLogModuleDhcpV6Layer,      ///< DhcpV6Layer module (Packet++)
		PacketLogModuleIgmpLayer,        ///< IgmpLayer module (Packet++)
		PacketLogModuleSipLayer,         ///< SipLayer module (Packet++)
		PacketLogModuleSdpLayer,         ///< SdpLayer module (Packet++)
		PacketLogModuleRadiusLayer,      ///< RadiusLayer module (Packet++)
		PacketLogModuleGtpLayer,         ///< GtpLayer module (Packet++)
		PacketLogModuleBgpLayer,         ///< GtpLayer module (Packet++)
		PacketLogModuleSSHLayer,         ///< SSHLayer module (Packet++)
		PacketLogModuleVrrpLayer,        ///< Vrrp Record module (Packet++)
		PacketLogModuleTcpReassembly,    ///< TcpReassembly module (Packet++)
		PacketLogModuleIPReassembly,     ///< IPReassembly module (Packet++)
		PacketLogModuleIPSecLayer,       ///< IPSecLayers module (Packet++)
		PacketLogModuleNtpLayer,         ///< NtpLayer module (Packet++)
		PacketLogModuleTelnetLayer,      ///< TelnetLayer module (Packet++)
		PacketLogModuleStpLayer,         ///< StpLayer module (Packet++)
		PacketLogModuleLLCLayer,         ///< LLCLayer module (Packet++)
		PacketLogModuleNdpLayer,         ///< NdpLayer module (Packet++)
		PacketLogModuleFtpLayer,         ///< FtpLayer module (Packet++)
		PacketLogModuleSomeIpLayer,      ///< SomeIpLayer module (Packet++)
		PacketLogModuleSomeIpSdLayer,    ///< SomeIpSdLayer module (Packet++)
		PacketLogModuleWakeOnLanLayer,   ///< WakeOnLanLayer module (Packet++)
		PacketLogModuleSmtpLayer,        ///< SmtpLayer module (Packet++)
		PcapLogModuleWinPcapLiveDevice,  ///< WinPcapLiveDevice module (VanHooks net layer)
		PcapLogModuleRemoteDevice,       ///< WinPcapRemoteDevice module (VanHooks net layer)
		PcapLogModuleLiveDevice,         ///< PcapLiveDevice module (VanHooks net layer)
		PcapLogModuleFileDevice,         ///< FileDevice module (VanHooks net layer)
		PcapLogModulePfRingDevice,       ///< PfRingDevice module (VanHooks net layer)
		PcapLogModuleMBufRawPacket,      ///< MBufRawPacket module (VanHooks net layer)
		PcapLogModuleDpdkDevice,         ///< DpdkDevice module (VanHooks net layer)
		PcapLogModuleKniDevice,          ///< KniDevice module (VanHooks net layer)
		PcapLogModuleXdpDevice,          ///< XdpDevice module (VanHooks net layer)
		NetworkUtils,                    ///< NetworkUtils module (VanHooks net layer)
		NumOfLogModules
	};

	/**
	 * @class Logger
	 * VanHooks logger manager.
	 * VanHooks uses this logger to output both error and debug logs.
	 * There are currently 3 log levels: Logger#Error, Logger#Info and Logger#Debug.
	 *
	 * VanHooks is divided into modules (described in #LogModule enum). The user can set the log level got each
	 * module or to all modules at once. The default is Logger#Info which outputs only error messages. Changing log
	 * level for modules can be done dynamically while the application is running.
	 *
	 * The logger also exposes a method to retrieve the last error log message.
	 *
	 * Logs are printed to console by default in a certain format. The user can set a different print function to change
	 * the format or to print to other media (such as files, etc.).
	 *
	 * VanHooks logger is a singleton which can be reached from anywhere in the code.
	 *
	 * Note: Logger#Info level logs are currently only used in DPDK devices to set DPDK log level to RTE_LOG_NOTICE.
	 */
	class Logger
	{
	public:
		/**
		 * An enum representing the log level. Currently 3 log levels are supported: Error, Info and Debug. Info is the
		 * default log level
		 */
		enum LogLevel
		{
			Error,  ///< Error log level
			Info,   ///< Info log level
			Debug   ///< Debug log level
		};

		/**
		 * @typedef LogPrinter
		 * Log printer callback. Used for printing the logs in a custom way.
		 * @param[in] logLevel The log level for this log message
		 * @param[in] logMessage The log message
		 * @param[in] file The source file in VanHooks code the log message is coming from
		 * @param[in] method The method in VanHooks code the log message is coming from
		 * @param[in] line The line in VanHooks code the log message is coming from
		 */
		typedef void (*LogPrinter)(LogLevel logLevel, const std::string& logMessage, const std::string& file,
		                           const std::string& method, const int line);

		/**
		 * A static method for converting the log level enum to a string.
		 * @param[in] logLevel A log level enum
		 * @return The log level as a string
		 */
		static std::string log_level_as_string(LogLevel logLevel);

		/**
		 * Get the log level for a certain module
		 * @param[in] module VanHooks module
		 * @return The log level set for this module
		 */
		LogLevel get_log_level(LogModule module)
		{
			return log_modules_array_[module];
		}

		/**
		 * Set the log level for a certain VanHooks module
		 * @param[in] module VanHooks module
		 * @param[in] level The log level to set the module to
		 */
		void set_log_level(LogModule module, LogLevel level)
		{
			log_modules_array_[module] = level;
		}

		/**
		 * Check whether a certain module is set to debug log level
		 * @param[in] module VanHooks module
		 * @return True if this module log level is "debug". False otherwise
		 */
		bool is_debug_enabled(LogModule module) const
		{
			return log_modules_array_[module] == Debug;
		}

		VH_DEPRECATED("use is_debug_enabled()")
		bool isDebugEnabled(LogModule module) const { return is_debug_enabled(module); }

		/**
		 * Set all VanHooks modules to a certain log level
		 * @param[in] level The log level to set all modules to
		 */
		void set_all_modules_to_log_level(LogLevel level)
		{
			for (int i = 1; i < NumOfLogModules; i++)
				log_modules_array_[i] = level;
		}

		/**
		 * Set a custom log printer.
		 * @param[in] printer A log printer function that will be called for every log message
		 */
		void set_log_printer(LogPrinter printer)
		{
			log_printer_ = printer;
		}

		/**
		 * Set the log printer back to the default printer
		 */
		void reset_log_printer()
		{
			log_printer_ = &default_log_printer;
		}

		/**
		 * @return Get the last error message
		 */
		std::string get_last_error()
		{
			return last_error_;
		}

		/**
		 * Suppress logs in all VanHooks modules
		 */
		void suppress_logs()
		{
			logs_enabled_ = false;
		}

		/**
		 * Enable logs in all VanHooks modules
		 */
		void enable_logs()
		{
			logs_enabled_ = true;
		}

		/**
		 * Get an indication if logs are currently enabled.
		 * @return True if logs are currently enabled, false otherwise
		 */
		bool logs_enabled() const
		{
			return logs_enabled_;
		}

		template <class T> Logger& operator<<(const T& msg)
		{
			(*log_stream_) << msg;
			return *this;
		}

		std::ostringstream* internal_create_log_stream();

		/**
		 * An internal method to print log messages. Shouldn't be used externally.
		 */
		void internal_print_log_message(std::ostringstream* logStream, Logger::LogLevel logLevel, const char* file,
		                             const char* method, int line);

		/**
		 * Get access to Logger singleton
		 * @todo: make this singleton thread-safe/
		 * @return a pointer to the Logger singleton
		 **/
		static Logger& get_instance()
		{
			static Logger instance;
			return instance;
		}

		VH_DEPRECATED("use get_instance()")
		static Logger& getInstance() { return get_instance(); }

	private:
		bool logs_enabled_;
		Logger::LogLevel log_modules_array_[NumOfLogModules];
		LogPrinter log_printer_;
		std::string last_error_;
		std::ostringstream* log_stream_;

		// private c'tor - this class is a singleton
		Logger();

		static void default_log_printer(LogLevel logLevel, const std::string& logMessage, const std::string& file,
		                              const std::string& method, const int line);
	};
}  // namespace vanhooks::net
// ---- end Logger.h ----

// ---- begin TablePrinter.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * A class for printing tables in command-line
	 */
	class TablePrinter
	{
	public:
		/**
		 * C'tor - get column names and column widths
		 * @param[in] columnNames A vector of strings containing column names
		 * @param[in] columnWidths A vector of integers containing column widths
		 */
		TablePrinter(std::vector<std::string> columnNames, std::vector<int> columnWidths);

		/**
		 * A d'tor for this class. Closes the table if not closed
		 */
		virtual ~TablePrinter();

		/**
		 * Print a single row by providing a single string containing all values delimited by a specified character.
		 * For example: if specified delimiter is '|' and there are 3 columns an example input can be:
		 * "value for column1|value for column2|value for column3"
		 * @param[in] values A string delimited by a specified delimiter that contains values for all columns
		 * @param[in] delimiter A delimiter that separates between values of different columns in the values string
		 * @return True if row was printed successfully or false otherwise (in any case of error an appropriate message
		 * will be printed to log)
		 */
		bool print_row(const std::string& values, char delimiter);

		/**
		 * Print a single row
		 * @param[in] values A vector of strings containing values for all columns
		 * @return True if row was printed successfully or false otherwise (in any case of error an appropriate message
		 * will be printed to log)
		 */
		bool print_row(std::vector<std::string> values);

		/**
		 * Print a separator line
		 */
		void print_separator();

		/**
		 * Close the table - should be called after all rows were printed. Calling this method is not a must as it's
		 * called in the class d'tor
		 */
		void close_table();

	private:
		std::vector<std::string> column_names_;
		std::vector<int> column_widths_;
		bool first_row_;
		bool table_closed_;

		/**
		 * Print the table headline
		 */
		void print_headline();
	};

}  // namespace vanhooks::net
// ---- end TablePrinter.h ----

// ---- begin PointerVector.h ----
#include <cstddef>
#include <stdio.h>
#include <stdint.h>
#include <stdexcept>
#include <vector>
#include <memory>


/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class PointerVector
	 * A template class for representing a std::vector of pointers. Once (a pointer to) an element is added to this
	 * vector, the element responsibility moves to the vector, meaning the PointerVector will free the object once it's
	 * removed from the vector This class wraps std::vector and adds the capability of freeing objects once they're
	 * removed from it
	 */
	template <typename T> class PointerVector
	{
	public:
		/**
		 * Iterator object that is used for iterating all elements in the vector
		 */
		using VectorIterator = typename std::vector<T*>::iterator;

		/**
		 * Const iterator object that is used for iterating all elements in a constant vector
		 */
		using ConstVectorIterator = typename std::vector<T*>::const_iterator;

		/**
		 * A constructor that create an empty instance of this object
		 */
		PointerVector()
		{}

		/**
		 * Copies the vector along with all elements inside it.
		 * All elements inside the copied vector are duplicates and the originals remain unchanged.
		 * @param[in] other The vector to copy from.
		 * @remarks As the vector is copied via deep copy, all pointers obtained from the copied vector
		 * reference the duplicates and not the originals.
		 */
		PointerVector(const PointerVector& other) : vector_(deep_copy_unsafe(other.vector_))
		{}

		/**
		 * Move constructor. All elements along with their ownership is transferred to the new vector.
		 * @param[in] other The vector to move from.
		 */
		PointerVector(PointerVector&& other) noexcept : vector_(std::move(other.vector_))
		{
			other.vector_.clear();
		}

		/**
		 * A destructor for this class. The destructor frees all elements that are binded to the vector
		 */
		~PointerVector()
		{
			free_vector_unsafe(vector_);
		}

		/**
		 * A copy assignment operator. Replaces the contents with a copy of the contents of other.
		 * See copy constructor for more information on the specific copy procedure.
		 * @param[in] other The vector to copy from.
		 * @return A reference to the current object.
		 */
		PointerVector& operator=(const PointerVector& other)
		{
			// Saves a copy of the old pointer to defer cleanup.
			auto oldValues = vector_;
			try
			{
				vector_ = deep_copy_unsafe(other.vector_);
			}
			// If an exception is thrown during the copy operation, restore old values and rethrow.
			catch (const std::exception&)
			{
				vector_ = std::move(oldValues);
				throw;
			}
			// Free old values as the new ones have been successfully assigned.
			free_vector_unsafe(oldValues);
			return *this;
		}

		/**
		 * A move assignment operator. Replaces the contents with those of other via move semantics.
		 * The other vector is left empty.
		 * @param[in] other The vector to move from.
		 * @return A reference to the current object.
		 */
		PointerVector& operator=(PointerVector&& other) noexcept
		{
			// Releases all current elements.
			clear();
			// Moves the elements of the other vector.
			vector_ = std::move(other.vector_);
			// Explicitly clear the other vector as the standard only guarantees an unspecified valid state after move.
			other.vector_.clear();
			return *this;
		}

		/**
		 * Clears all elements of the vector while freeing them
		 */
		void clear()
		{
			free_vector_unsafe(vector_);
			vector_.clear();
		}

		/**
		 * Adding a nullptr to the vector is not allowed.
		 */
		void push_back(std::nullptr_t element, bool freeElementOnError = true) = delete;

		/**
		 * Add a new (pointer to an) element to the vector
		 * @param[in] element A pointer to an element to assume ownership of.
		 * @param[in] freeElementOnError If set to true, the element is freed if an exception is thrown during the push.
		 * @throws std::invalid_argument The provided pointer is a nullptr.
		 */
		void push_back(T* element, bool freeElementOnError = true)
		{
			if (element == nullptr)
			{
				throw std::invalid_argument("Element is nullptr");
			}

			try
			{
				vector_.push_back(element);
			}
			catch (const std::exception&)
			{
				if (freeElementOnError)
				{
					delete element;
				}
				throw;
			}
		}

		/**
		 * Add a new element to the vector that has been managed by an unique pointer.
		 * @param[in] element A unique pointer holding an element.
		 * @throws std::invalid_argument The provided pointer is a nullptr.
		 * @remarks If push_back throws the element is freed immediately.
		 */
		void push_back(std::unique_ptr<T> element)
		{
			if (!element)
			{
				throw std::invalid_argument("Element is nullptr");
			}

			// Release is called after the raw pointer is already inserted into the vector to prevent
			// a memory leak if push_back throws.
			// cppcheck-suppress danglingLifetime
			vector_.push_back(element.get());
			element.release();
		}

		// ---- Legacy upstream-style aliases (source compat; prefer the snake_case API above) ----
		VH_DEPRECATED("use push_back()")
		void pushBack(T* element, bool freeElementOnError = true) { push_back(element, freeElementOnError); }
		VH_DEPRECATED("use push_back()")
		void pushBack(std::unique_ptr<T> element) { push_back(std::move(element)); }

		/**
		 * Get the first element of the vector
		 * @return An iterator object pointing to the first element of the vector
		 */
		VectorIterator begin()
		{
			return vector_.begin();
		}

		/**
		 * Get the first element of a constant vector
		 * @return A const iterator object pointing to the first element of the vector
		 */
		ConstVectorIterator begin() const
		{
			return vector_.begin();
		}

		/**
		 * Get the last element of the vector
		 * @return An iterator object pointing to the last element of the vector
		 */
		VectorIterator end()
		{
			return vector_.end();
		}

		/**
		 * Get the last element of a constant vector
		 * @return A const iterator object pointing to the last element of the vector
		 */
		ConstVectorIterator end() const
		{
			return vector_.end();
		}

		/**
		 * Get number of elements in the vector
		 * @return The number of elements in the vector
		 */
		size_t size() const
		{
			return vector_.size();
		}

		/**
		 * @return A pointer of the first element in the vector
		 */
		T* front()
		{
			return vector_.front();
		}

		/**
		 * @return A pointer to the first element in the vector
		 */
		T const* front() const
		{
			return vector_.front();
		}

		/**
		 * @return A pointer to the last element in the vector
		 */
		T* back()
		{
			return vector_.back();
		}

		/*
		 * @return A pointer to the last element in the vector.
		 */
		T const* back() const
		{
			return vector_.back();
		}

		/**
		 * Removes from the vector a single element (position). Once the element is erased, it's also freed
		 * @param[in] position The position of the element to erase
		 * @return An iterator pointing to the new location of the element that followed the last element erased by the
		 * function call
		 */
		VectorIterator erase(VectorIterator position)
		{
			delete (*position);
			return vector_.erase(position);
		}

		/**
		 * Remove an element from the vector without freeing it
		 * @param[in, out] position The position of the element to remove from the vector.
		 * The iterator is shifted to the following element after the removal is completed.
		 * @return A pointer to the element which is no longer managed by the vector. It's user responsibility to free
		 * it
		 * @deprecated Deprecated in favor of 'get_and_detach' as that function provides memory safety.
		 */
		VH_DEPRECATED("Please use the memory safe 'get_and_detach' instead.")
		T* get_and_remove_from_vector(VectorIterator& position)
		{
			T* result = *position;
			position = vector_.erase(position);
			return result;
		}

		/**
		 * Removes an element from the vector and transfers ownership to the returned unique pointer.
		 * @param[in] index The index of the element to detach.
		 * @return An unique pointer that holds ownership of the detached element.
		 */
		std::unique_ptr<T> get_and_detach(size_t index)
		{
			return get_and_detach(vector_.begin() + index);
		}

		/**
		 * Removes an element from the vector and transfers ownership to the returned unique pointer.
		 * @param[in, out] position An iterator pointing to the element to detach.
		 * The iterator is shifted to the following element after the detach completes.
		 * @return An unique pointer that holds ownership of the detached element.
		 */
		std::unique_ptr<T> get_and_detach(VectorIterator& position)
		{
			std::unique_ptr<T> result(*position);
			position = vector_.erase(position);
			return result;
		}

		/**
		 * Removes an element from the vector and transfers ownership to the returned unique pointer.
		 * @param[in] position An iterator pointing to the element to detach.
		 * @return An unique pointer that holds ownership of the detached element.
		 */
		std::unique_ptr<T> get_and_detach(VectorIterator const& position)
		{
			std::unique_ptr<T> result(*position);
			vector_.erase(position);
			return result;
		}

		VH_DEPRECATED("use get_and_detach()")
		std::unique_ptr<T> getAndDetach(size_t index) { return get_and_detach(index); }
		VH_DEPRECATED("use get_and_detach()")
		std::unique_ptr<T> getAndDetach(VectorIterator& position) { return get_and_detach(position); }
		VH_DEPRECATED("use get_and_detach()")
		std::unique_ptr<T> getAndDetach(VectorIterator const& position) { return get_and_detach(position); }

		/**
		 * Return a pointer to the element in a certain index
		 * @param[in] index The index to retrieve the element from
		 * @return The element at the specified position in the vector
		 */
		T* at(int index)
		{
			return vector_.at(index);
		}

		/**
		 * Return a const pointer to the element in a certain index
		 * @param[in] index The index to retrieve the element from
		 * @return The element at the specified position in the vector
		 */
		const T* at(int index) const
		{
			return vector_.at(index);
		}

	private:
		/**
		 * Performs a copy of the vector along with its elements.
		 * The caller is responsible of freeing the copied elements.
		 * @return A vector of pointers to the newly copied elements.
		 */
		static std::vector<T*> deep_copy_unsafe(std::vector<T*> const& origin)
		{
			std::vector<T*> copyVec;

			try
			{
				for (const auto iter : origin)
				{
					T* objCopy = new T(*iter);
					try
					{
						copyVec.push_back(objCopy);
					}
					catch (const std::exception&)
					{
						delete objCopy;
						throw;
					}
				}
			}
			catch (const std::exception&)
			{
				for (auto obj : copyVec)
				{
					delete obj;
				}
				throw;
			}

			return copyVec;
		}

		/**
		 * Frees all elements inside the vector.
		 * Calling this function with non-heap allocated pointers is UB.
		 * @param[in] origin The vector of elements to free.
		 * @remarks The vector's contents are not cleared and will point to invalid locations in memory.
		 */
		static void free_vector_unsafe(std::vector<T*> const& origin)
		{
			for (auto& obj : origin)
			{
				delete obj;
			}
		}

		std::vector<T*> vector_;
	};

}  // namespace vanhooks::net
// ---- end PointerVector.h ----

// ---- begin LRUList.h ----
#include <list>
#include <unordered_map>

#if __cplusplus > 199711L || _MSC_VER >= 1800
#	include <utility>
#endif

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class LRUList
	 * A template class that implements a LRU cache with limited size. Each time the user puts an element it goes to
	 * head of the list as the most recently used element (if the element was already in the list it advances to the
	 * head of the list). The last element in the list is the one least recently used and will be pulled out of the list
	 * if it reaches its max size and a new element comes in. All actions on this LRU list are O(1)
	 */
	template <typename T> class LRUList
	{
	public:
		typedef typename std::list<T>::iterator ListIterator;
		typedef typename std::unordered_map<T, ListIterator>::iterator MapIterator;

		/**
		 * A c'tor for this class
		 * @param[in] maxSize The max size this list can go
		 */
		explicit LRUList(size_t maxSize)
		{
			max_size_ = maxSize;
		}

		/**
		 * Puts an element in the list. This element will be inserted (or advanced if it already exists) to the head of
		 * the list as the most recently used element. If the list already reached its max size and the element is new
		 * this method will remove the least recently used element and return a value in deletedValue. Method complexity
		 * is O(log(get_size())). This is a optimized version of the method T* put(const T&).
		 * @param[in] element The element to insert or to advance to the head of the list (if already exists)
		 * @param[out] deletedValue The value of deleted element if a pointer is not nullptr. This parameter is
		 * optional.
		 * @return 0 if the list didn't reach its max size, 1 otherwise. In case the list already reached its max size
		 * and deletedValue is not nullptr the value of deleted element is copied into the place the deletedValue points
		 * to.
		 */
		int put(const T& element, T* deletedValue = nullptr)
		{
			cache_items_list_.push_front(element);

			// Inserting a new element. If an element with an equivalent key already exists the method returns an
			// iterator to the element that prevented the insertion
			std::pair<MapIterator, bool> pair =
			    cache_items_map_.insert(std::make_pair(element, cache_items_list_.begin()));
			if (pair.second == false)  // already exists
			{
				cache_items_list_.erase(pair.first->second);
				pair.first->second = cache_items_list_.begin();
			}

			if (cache_items_map_.size() > max_size_)
			{
				ListIterator lruIter = cache_items_list_.end();
				--lruIter;

				if (deletedValue != nullptr)
#if __cplusplus > 199711L || _MSC_VER >= 1800
					*deletedValue = std::move(*lruIter);
#else
					*deletedValue = *lruIter;
#endif
				cache_items_map_.erase(*lruIter);
				cache_items_list_.erase(lruIter);
				return 1;
			}

			return 0;
		}

		/**
		 * Get the most recently used element (the one at the beginning of the list)
		 * @return The most recently used element
		 */
		const T& get_mru_element() const
		{
			return cache_items_list_.front();
		}

		/**
		 * Get the least recently used element (the one at the end of the list)
		 * @return The least recently used element
		 */
		const T& get_lru_element() const
		{
			return cache_items_list_.back();
		}

		/**
		 * Erase an element from the list. If element isn't found in the list nothing happens
		 * @param[in] element The element to erase
		 */
		void erase_element(const T& element)
		{
			MapIterator iter = cache_items_map_.find(element);
			if (iter == cache_items_map_.end())
				return;

			cache_items_list_.erase(iter->second);
			cache_items_map_.erase(iter);
		}

		/**
		 * @return The max size of this list as determined in the c'tor
		 */
		size_t get_max_size() const
		{
			return max_size_;
		}

		VH_DEPRECATED("use erase_element()")
		void eraseElement(const T& element) { erase_element(element); }
		VH_DEPRECATED("use get_max_size()")
		size_t getMaxSize() const { return get_max_size(); }

		/**
		 * @return The number of elements currently in this list
		 */
		size_t get_size() const
		{
			return cache_items_map_.size();
		}

	private:
		std::list<T> cache_items_list_;
		std::unordered_map<T, ListIterator> cache_items_map_;
		size_t max_size_;
	};

}  // namespace vanhooks::net
// ---- end LRUList.h ----

// ---- begin TimespecTimeval.h ----
/// these conversion macros are not defined on some of the platforms, including
/// Windows

#ifndef TIMEVAL_TO_TIMESPEC
#	define TIMEVAL_TO_TIMESPEC(tv, ts)                                                                                \
		{                                                                                                              \
			(ts)->tv_sec = (tv)->tv_sec;                                                                               \
			(ts)->tv_nsec = (tv)->tv_usec * 1000;                                                                      \
		}
#endif

#ifndef TIMESPEC_TO_TIMEVAL
#	define TIMESPEC_TO_TIMEVAL(tv, ts)                                                                                \
		{                                                                                                              \
			(tv)->tv_sec = (ts)->tv_sec;                                                                               \
			(tv)->tv_usec = (ts)->tv_nsec / 1000;                                                                      \
		}
#endif
// ---- end TimespecTimeval.h ----

// ---- begin VersionInfo.h ----
// Network layer version info — part of VanHooks
#define VH_NET_VERSION_MAJOR 24
#define VH_NET_VERSION_MINOR 9
#define VH_NET_VERSION_PATCH 0
namespace vanhooks::net {
    inline const char* get_vanhooks_version_full() { return "VanHooks net layer"; }
    inline const char* get_vanhooks_version()     { return "24.09"; }
}
// ---- end VersionInfo.h ----

// ---- begin OUILookup.h ----
#include <unordered_map>
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @class OUILookup
	 * Provides vendor name matching functionality from MAC addresses. It uses an internal database to define name of
	 * the vendor. The class itself should be initialized by using init_oui_database_from_json() otherwise all requests will
	 * return "Unknown" as vendor. The class itself currently does not support on-fly modifying the database but anyone
	 * who wants to add/modify/remove entries, should modify 3rdParty/OUILookup/VH_OUIDatabase.json file and call to
	 * init_oui_database_from_json() function to renew the internal data.
	 */
	class OUILookup
	{
	private:
		/**
		 * MAC addresses with mask values. For example for a MAC address "XX:XX:XX:XX:X0:00/36" the first element will
		 * be 36, and the second element will be unsigned integer equivalent of "XX:XX:XX:XX:X0:00" and vendor name.
		 */
		struct MaskedFilter
		{
			int mask;
			std::unordered_map<uint64_t, std::string> vendorMap;
		};

		/// Vendors for MAC addresses and mask filters if exists
		struct VendorData
		{
			std::string vendorName;
			std::vector<MaskedFilter> maskedFilter;
		};

		/**
		 * MAC addresses with only first three octets. The first element is unsigned integer equivalent of "XX:XX:XX"
		 * formatted MAC address
		 */
		typedef std::unordered_map<uint64_t, VendorData> OUIVendorMap;

		/// Internal vendor list for MAC addresses
		OUIVendorMap vendorMap;

		template <typename T> int64_t internal_parser(T& jsonData);

	public:
		/**
		 * Initialise internal OUI database from a JSON file
		 * @param[in] path Path to OUI database. The database itself is located at
		 * 3rdParty/OUILookup/VH_OUIDatabase.json
		 * @return Returns the number of total vendors, negative on errors
		 */
		int64_t init_oui_database_from_json(const std::string& path = "");

		/**
		 * Returns the vendor of the MAC address. OUI database should be initialized with init_oui_database_from_json()
		 * @param[in] addr MAC address to search
		 * @return Vendor name
		 */
		std::string get_vendor_name(const vanhooks::net::MacAddress& addr);
	};
}  // namespace vanhooks::net
// ---- end OUILookup.h ----

// ---- begin md5.h ----
// //////////////////////////////////////////////////////////
// md5.h
// Copyright (c) 2014 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//


//#include "hash.h"
#include <string>
#include <stdint.h>

/// compute MD5 hash
/** Usage:
    MD5 md5;
    std::string myHash  = md5("Hello World");     // std::string
    std::string myHash2 = md5("How are you", 11); // arbitrary data, 11 bytes

    // or in a streaming fashion:

    MD5 md5;
    while (more data available)
      md5.add(pointer to fresh data, number of new bytes);
    std::string myHash3 = md5.get_hash();
  */
class MD5 //: public Hash
{
public:
  /// split into 64 byte blocks (=> 512 bits), hash is 16 bytes long
  enum { BlockSize = 512 / 8, HashBytes = 16 };

  /// same as reset()
  MD5();

  /// compute MD5 of a memory block
  std::string operator()(const void* data, size_t numBytes);
  /// compute MD5 of a string, excluding final zero
  std::string operator()(const std::string& text);

  /// add arbitrary number of bytes
  void add(const void* data, size_t numBytes);

  /// return latest hash as 32 hex characters
  std::string get_hash();
  /// return latest hash as bytes
  void        get_hash(unsigned char buffer[HashBytes]);

  /// restart
  void reset();

private:
  /// process 64 bytes
  void process_block(const void* data);
  /// process everything left in the internal buffer
  void process_buffer();

  /// size of processed data in bytes
  uint64_t num_bytes_;
  /// valid bytes in buffer_
  size_t   buffer_size_;
  /// bytes not processed yet
  uint8_t  buffer_[BlockSize];

  enum { HashValues = HashBytes / 4 };
  /// hash, stored as integers
  uint32_t hash_[HashValues];
};
// ---- end md5.h ----

