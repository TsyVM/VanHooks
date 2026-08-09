#pragma once

// ===== Consolidated header: Devices.h =====
// Merges: PcapFilter, Device, PcapDevice, PcapFileDevice, PcapLiveDevice, PcapLiveDeviceList, WinPcapLiveDevice, PcapRemoteDevice, PcapRemoteDeviceList, PcapUtils, DeviceUtils, RawSocketDevice, NetworkUtils
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "PacketCore.h"
#include "L2Layers.h"
#include "Common.h"

// ---- begin PcapFilter.h ----
#include <string>
#include <vector>
#include <memory>
#include <stdint.h>

// Forward Declaration - used in GeneralFilter
struct bpf_program;

/**
 * @file
 * Most packet capture engines contain packet filtering capabilities. In order to set the filters there should be a
 * known syntax user can use. The most popular syntax is Berkeley Packet Filter (BPF) - see more in here:
 * http://en.wikipedia.org/wiki/Berkeley_Packet_Filter. Detailed explanation of the syntax can be found here:
 * http://www.tcpdump.org/manpages/pcap-filter.7.html.
 *
 * The problem with BPF is that, for my opinion, the syntax is too complicated and too poorly documented. In addition
 * the BPF filter compilers may output syntax errors that are hard to understand. My experience with BPF was not good,
 * so I decided to make the filters mechanism more structured, easier to understand and less error-prone by creating
 * classes that represent filters. Each possible filter phrase is represented by a class. The filter, at the end, is
 * that class.
 * For example: the filter "src net 1.1.1.1" will be represented by IPFilter instance; "dst port 80"
 * will be represented by PortFilter, and so on.
 * So what about complex filters that involve "and", "or"? There are
 * also 2 classes: AndFilter and OrFilter that can store more filters (in a composite idea) and connect them by "and" or
 * "or". For example: "src host 1.1.1.1 and dst port 80" will be represented by an AndFilter that holds IPFilter and
 * PortFilter inside it
 */

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	// Forward Declaration - used in GeneralFilter
	class RawPacket;

	/**
	 * An enum that contains direction (source or destination)
	 */
	typedef enum
	{
		/** Source */
		SRC,
		/** Destination */
		DST,
		/** Source or destination */
		SRC_OR_DST
	} Direction;

	/**
	 * Supported operators enum
	 */
	typedef enum
	{
		/** Equals */
		EQUALS,
		/** Not equals */
		NOT_EQUALS,
		/** Greater than */
		GREATER_THAN,
		/** Greater or equal */
		GREATER_OR_EQUAL,
		/** Less than */
		LESS_THAN,
		/** Less or equal */
		LESS_OR_EQUAL
	} FilterOperator;

	namespace internal
	{
		/**
		 * @class BpfProgramDeleter
		 * A deleter that cleans up a bpf_program object.
		 */
		struct BpfProgramDeleter
		{
			void operator()(bpf_program* ptr) const;
		};
	}  // namespace internal

	/**
	 * @class BpfFilterWrapper
	 * A wrapper class for BPF filtering. Enables setting a BPF filter and matching it against a packet
	 */
	class BpfFilterWrapper
	{
	private:
		std::string filter_str_;
		LinkLayerType link_type_;
		std::unique_ptr<bpf_program, internal::BpfProgramDeleter> program_;

		void free_program();

	public:
		/**
		 * A c'tor for this class
		 */
		BpfFilterWrapper();

		/**
		 * A copy constructor for this class.
		 * @param[in] other The instance to copy from
		 */
		BpfFilterWrapper(const BpfFilterWrapper& other);

		/**
		 * A copy assignment operator for this class.
		 * @param[in] other An instance of IPNetwork to assign
		 * @return A reference to the assignee
		 */
		BpfFilterWrapper& operator=(const BpfFilterWrapper& other);

		/**
		 * Set a filter. This method receives a filter in BPF syntax (https://biot.com/capstats/bpf.html) and an
		 * optional link type, compiles them, and if compilation is successful it stores the filter.
		 * @param[in] filter A filter in BPF syntax
		 * @param[in] linkType An optional parameter to set the filter's link type. The default is LINKTYPE_ETHERNET
		 * @return True if compilation is successful and filter is stored in side this object, false otherwise
		 */
		bool set_filter(const std::string& filter, LinkLayerType linkType = LINKTYPE_ETHERNET);

		/**
		 * Match a packet with the filter stored in this object. If the filter is empty the method returns "true".
		 * If the link type of the raw packet is different than the one set in set_filter(), the filter will be
		 * re-compiled and stored in the object.
		 * @param[in] rawPacket A pointer to a raw packet which the filter will be matched against
		 * @return True if the filter matches (or if it's empty). False if the packet doesn't match or if the filter
		 * could not be compiled
		 */
		bool match_packet_with_filter(const RawPacket* rawPacket);

		/**
		 * Match a packet data with the filter stored in this object. If the filter is empty the method returns "true".
		 * If the link type provided is different than the one set in set_filter(), the filter will be re-compiled
		 * and stored in the object.
		 * @param[in] packetData A byte stream containing the packet data
		 * @param[in] packetDataLength The length in [bytes] of the byte stream
		 * @param[in] packetTimestamp The packet timestamp
		 * @param[in] linkType The packet link type
		 * @return True if the filter matches (or if it's empty). False if the packet doesn't match or if the filter
		 * could not be compiled
		 */
		bool match_packet_with_filter(const uint8_t* packetData, uint32_t packetDataLength, timespec packetTimestamp,
		                           uint16_t linkType);
	};

	/**
	 * @class GeneralFilter
	 * The base class for all filter classes. This class is virtual and abstract, hence cannot be instantiated.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class GeneralFilter
	{
	protected:
		BpfFilterWrapper bpf_wrapper_;

	public:
		/**
		 * A method that parses the class instance into BPF string format
		 * @param[out] result An empty string that the parsing will be written into. If the string isn't empty, its
		 * content will be overridden
		 */
		virtual void parse_to_string(std::string& result) = 0;

		/**
		 * Match a raw packet with a given BPF filter.
		 * @param[in] rawPacket A pointer to the raw packet to match the BPF filter with
		 * @return True if a raw packet matches the BPF filter or false otherwise
		 */
		bool match_packet_with_filter(RawPacket* rawPacket);

		GeneralFilter()
		{}

		/**
		 * Virtual destructor, frees the bpf program
		 */
		virtual ~GeneralFilter()
		{}
	};

	/**
	 * @class BPFStringFilter
	 * This class can be loaded with a BPF filter string and then can be used to verify the string is valid.
	 */
	class BPFStringFilter : public GeneralFilter
	{
	private:
		const std::string filter_str_;

	public:
		explicit BPFStringFilter(const std::string& filterStr) : filter_str_(filterStr)
		{}

		virtual ~BPFStringFilter()
		{}

		/**
		 * A method that parses the class instance into BPF string format
		 * @param[out] result An empty string that the parsing will be written into. If the string isn't empty, its
		 * content will be overridden If the filter is not valid the result will be an empty string
		 */
		void parse_to_string(std::string& result) override;

		/**
		 * Verify the filter is valid
		 * @return True if the filter is valid or false otherwise
		 */
		bool verify_filter();
	};

	/**
	 * @class IFilterWithDirection
	 * An abstract class that is the base class for all filters which contain a direction (source or destination). This
	 * class cannot be instantiated
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IFilterWithDirection : public GeneralFilter
	{
	private:
		Direction dir_;

	protected:
		void parse_direction(std::string& directionAsString);
		Direction get_dir() const
		{
			return dir_;
		}
		explicit IFilterWithDirection(Direction dir)
		{
			dir_ = dir;
		}

	public:
		/**
		 * Set the direction for the filter (source or destination)
		 * @param[in] dir The direction
		 */
		void set_direction(Direction dir)
		{
			dir_ = dir;
		}
	};

	/**
	 * @class IFilterWithOperator
	 * An abstract class that is the base class for all filters which contain an operator (e.g X equals Y; A is greater
	 * than B; Z1 not equals Z2, etc.). This class cannot be instantiated
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IFilterWithOperator : public GeneralFilter
	{
	private:
		FilterOperator operator_;

	protected:
		std::string parse_operator();
		FilterOperator get_operator() const
		{
			return operator_;
		}
		explicit IFilterWithOperator(FilterOperator op)
		{
			operator_ = op;
		}

	public:
		/**
		 * Set the operator for the filter
		 * @param[in] op The operator to set
		 */
		void set_operator(FilterOperator op)
		{
			operator_ = op;
		}
	};

	/**
	 * @class IPFilter
	 * A class for representing IPv4 or IPv6 address filter, equivalent to "net src x.x.x.x" or "net dst x.x.x.x"
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IPFilter : public IFilterWithDirection
	{
	private:
		IPAddress address_;
		IPNetwork network_;

	public:
		/**
		 * The basic constructor that creates the filter from an IP address string and direction (source or destination)
		 * @param[in] ipAddress The IP address to build the filter with.
		 * @param[in] dir The address direction to filter (source or destination)
		 * @throws std::invalid_argument The provided address is not a valid IPv4 or IPv6 address.
		 */
		IPFilter(const std::string& ipAddress, Direction dir) : IPFilter(IPAddress(ipAddress), dir)
		{}

		/**
		 * The basic constructor that creates the filter from an IP address and direction (source or destination)
		 * @param[in] ipAddress The IP address to build the filter with.
		 * @param[in] dir The address direction to filter (source or destination)
		 */
		IPFilter(const IPAddress& ipAddress, Direction dir)
		    : IFilterWithDirection(dir), address_(ipAddress), network_(ipAddress)
		{}

		/**
		 * A constructor that enable to filter only part of the address by using a mask (aka subnet). For example:
		 * "filter only IP addresses that matches the subnet 10.0.0.x"
		 * @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be matched.
		 * For example: if the address is "1.2.3.4" and the mask is "255.255.255.0" than the part of the address that
		 * will be matched is "1.2.3.X".
		 * @param[in] dir The address direction to filter (source or destination)
		 * @param[in] netmask The mask to use. The mask should be a valid IP address in either IPv4 dotted-decimal
		 * format (e.g., 255.255.255.0) or IPv6 colon-separated hexadecimal format (e.g., FFFF:FFFF:FFFF:FFFF::).
		 * @throws std::invalid_argument The provided address is not a valid IP address or the provided netmask string
		 * is invalid..
		 */
		IPFilter(const std::string& ipAddress, Direction dir, const std::string& netmask)
		    : IPFilter(IPv4Address(ipAddress), dir, netmask)
		{}

		/**
		 * A constructor that enable to filter only part of the address by using a mask (aka subnet). For example:
		 * "filter only IP addresses that matches the subnet 10.0.0.x"
		 * @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be
		 * matched. For example: if the address is "1.2.3.4" and the mask is "255.255.255.0" than the part of the
		 * address that will be matched is "1.2.3.X".
		 * @param[in] dir The address direction to filter (source or destination)
		 * @param[in] netmask The mask to use. The mask should be a valid IP address in either IPv4 dotted-decimal
		 * format (e.g., 255.255.255.0) or IPv6 colon-separated hexadecimal format (e.g., FFFF:FFFF:FFFF:FFFF::).
		 * @throws std::invalid_argument The provided netmask string is invalid.
		 */
		IPFilter(const IPAddress& ipAddress, Direction dir, const std::string& netmask)
		    : IFilterWithDirection(dir), address_(ipAddress), network_(ipAddress, netmask)
		{}

		/**
		 * A constructor that enables to filter by a subnet. For example: "filter only IP addresses that matches the
		 * subnet 10.0.0.3/24" which means the part of the address that will be matched is "10.0.0.X"
		 * @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be matched.
		 * For example: if the address is "1.2.3.4" and the subnet is "/24" than the part of the address that will be
		 * matched is "1.2.3.X".
		 * @param[in] dir The address direction to filter (source or destination)
		 * @param[in] len The subnet to use (e.g "/24"). Acceptable subnet values are [0, 32] for IPv4 and [0, 128] for
		 * IPv6.
		 * @throws std::invalid_argument The provided address is not a valid IPv4 or IPv6 address or the provided length
		 * is out of acceptable range.
		 */
		IPFilter(const std::string& ipAddress, Direction dir, int len) : IPFilter(IPAddress(ipAddress), dir, len)
		{}

		/**
		 * A constructor that enables to filter by a subnet. For example: "filter only IP addresses that matches the
		 * subnet 10.0.0.3/24" which means the part of the address that will be matched is "10.0.0.X"
		 * @param[in] ipAddress The IP address to use. Only the part of the address that is not masked will be matched.
		 * For example: if the address is "1.2.3.4" and the subnet is "/24" than the part of the address that will be
		 * matched is "1.2.3.X".
		 * @param[in] dir The address direction to filter (source or destination)
		 * @param[in] len The subnet to use (e.g "/24"). Acceptable subnet values are [0, 32] for IPv4 and [0, 128] for
		 * IPv6.
		 * @throws std::invalid_argument The provided length is out of acceptable range.
		 */
		IPFilter(const IPAddress& ipAddress, Direction dir, int len)
		    : IFilterWithDirection(dir), address_(ipAddress), network_(ipAddress, len)
		{}

		/**
		 * A constructor that enables to filter by a predefined network object.
		 * @param[in] network The network to use when filtering. IP address and subnet mask are taken from the network
		 * object.
		 * @param[in] dir The address direction to filter (source or destination)
		 */
		IPFilter(const IPNetwork& network, Direction dir)
		    : IFilterWithDirection(dir), address_(network.get_network_prefix()), network_(network)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the network to build the filter with.
		 * @param[in] network The IP Network object to be used when building the filter.
		 */
		void set_network(const IPNetwork& network)
		{
			network_ = network;
			address_ = network_.get_network_prefix();
		}

		/**
		 * Set the IP address
		 * @param[in] ipAddress The IP address to build the filter with.
		 * @throws std::invalid_argument The provided string does not represent a valid IP address.
		 */
		void set_addr(const std::string& ipAddress)
		{
			this->set_addr(IPAddress(ipAddress));
		}

		/**
		 * Set the IP address
		 * @param[in] ipAddress The IP address to build the filter with.
		 * @remarks Alternating between IPv4 and IPv6 can have unintended consequences on the subnet mask.
		 *  Setting an IPv4 address when the prefix length is over 32 make the new prefix length 32.
		 *  Setting an IPv6 address will keep the current IPv4 prefix mask length.
		 */
		void set_addr(const IPAddress& ipAddress)
		{
			address_ = ipAddress;
			uint8_t newPrefixLen = network_.get_prefix_len();
			if (address_.is_ipv4() && newPrefixLen > 32u)
			{
				newPrefixLen = 32u;
			}

			network_ = IPNetwork(address_, newPrefixLen);
		}

		/**
		 * Set the subnet mask
		 * @param[in] netmask The mask to use. The mask should match the IP version and be in a valid format.
		 * Valid formats:
		 *   IPv4 - (X.X.X.X) - 'X' - a number in the range of 0 and 255 (inclusive)):
		 *   IPv6 - (YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY:YYYY) - 'Y' - a hexadecimal digit [0 - 9, A - F]. Short form
		 *   IPv6 formats are allowed.
		 * @throws std::invalid_argument The provided netmask is invalid or does not correspond to the current IP
		 * address version.
		 */
		void set_mask(const std::string& netmask)
		{
			network_ = IPNetwork(address_, netmask);
		}

		/**
		 * Clears the subnet mask.
		 */
		void clear_mask()
		{
			this->clear_len();
		}

		/**
		 * Set the subnet (IPv4) or prefix length (IPv6).
		 * Acceptable subnet values are [0, 32] for IPv4 and [0, 128] for IPv6.
		 * @param[in] len The subnet to use (e.g "/24")
		 * @throws std::invalid_argument The provided length is out of acceptable range.
		 */
		void set_len(const int len)
		{
			network_ = IPNetwork(address_, len);
		}

		/**
		 * Clears the subnet mask length.
		 */
		void clear_len()
		{
			network_ = IPNetwork(address_);
		}
	};

	/**
	 * @class IPv4IDFilter
	 * A class for filtering IPv4 traffic by IP ID field of the IPv4 protocol, for example:
	 * "filter only IPv4 traffic which IP ID is greater than 1234"
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IPv4IDFilter : public IFilterWithOperator
	{
	private:
		uint16_t ip_id_;

	public:
		/**
		 * A constructor that gets the IP ID to filter and the operator and creates the filter out of them
		 * @param[in] ipID The IP ID to filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		IPv4IDFilter(uint16_t ipID, FilterOperator op) : IFilterWithOperator(op), ip_id_(ipID)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the IP ID to filter
		 * @param[in] ipID The IP ID to filter
		 */
		void set_ip_id(uint16_t ipID)
		{
			ip_id_ = ipID;
		}
	};

	/**
	 * @class IPv4TotalLengthFilter
	 * A class for filtering IPv4 traffic by "total length" field of the IPv4 protocol, for example:
	 * "filter only IPv4 traffic which "total length" value is less than 60B"
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class IPv4TotalLengthFilter : public IFilterWithOperator
	{
	private:
		uint16_t total_length_;

	public:
		/**
		 * A constructor that gets the total length to filter and the operator and creates the filter out of them
		 * @param[in] totalLength The total length value to filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		IPv4TotalLengthFilter(uint16_t totalLength, FilterOperator op)
		    : IFilterWithOperator(op), total_length_(totalLength)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the total length value
		 * @param[in] totalLength The total length value to filter
		 */
		void set_total_length(uint16_t totalLength)
		{
			total_length_ = totalLength;
		}
	};

	/**
	 * @class PortFilter
	 * A class for filtering TCP or UDP traffic by port, for example: "dst port 80" or "src port 12345".
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class PortFilter : public IFilterWithDirection
	{
	private:
		std::string port_;
		void port_to_string(uint16_t portAsInt);

	public:
		/**
		 * A constructor that gets the port and the direction and creates the filter
		 * @param[in] port The port to create the filter with
		 * @param[in] dir The port direction to filter (source or destination)
		 */
		PortFilter(uint16_t port, Direction dir);

		void parse_to_string(std::string& result) override;

		/**
		 * Set the port
		 * @param[in] port The port to create the filter with
		 */
		void set_port(uint16_t port)
		{
			port_to_string(port);
		}
	};

	/**
	 * @class PortRangeFilter
	 * A class for filtering TCP or UDP port ranges, meaning match only packets which port is within this range, for
	 * example: "src portrange 1000-2000" will match only TCP or UDP traffic which source port is in the range of 1000 -
	 * 2000
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class PortRangeFilter : public IFilterWithDirection
	{
	private:
		uint16_t from_port_;
		uint16_t to_port_;

	public:
		/**
		 * A constructor that gets the port range the the direction and creates the filter with them
		 * @param[in] fromPort The lower end of the port range
		 * @param[in] toPort The higher end of the port range
		 * @param[in] dir The port range direction to filter (source or destination)
		 */
		PortRangeFilter(uint16_t fromPort, uint16_t toPort, Direction dir)
		    : IFilterWithDirection(dir), from_port_(fromPort), to_port_(toPort)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the lower end of the port range
		 * @param[in] fromPort The lower end of the port range
		 */
		void set_from_port(uint16_t fromPort)
		{
			from_port_ = fromPort;
		}

		/**
		 * Set the higher end of the port range
		 * @param[in] toPort The higher end of the port range
		 */
		void set_to_port(uint16_t toPort)
		{
			to_port_ = toPort;
		}
	};

	/**
	 * @class MacAddressFilter
	 * A class for filtering Ethernet traffic by MAC addresses, for example: "ether src 12:34:56:78:90:12" or "ether dst
	 * 10:29:38:47:56:10:29"
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class MacAddressFilter : public IFilterWithDirection
	{
	private:
		MacAddress mac_address_;

	public:
		/**
		 * A constructor that gets the MAC address and the direction and creates the filter with them
		 * @param[in] address The MAC address to use for filtering
		 * @param[in] dir The MAC address direction to filter (source or destination)
		 */
		MacAddressFilter(MacAddress address, Direction dir) : IFilterWithDirection(dir), mac_address_(address)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the MAC address
		 * @param[in] address The MAC address to use for filtering
		 */
		void set_mac_address(MacAddress address)
		{
			mac_address_ = address;
		}
	};

	/**
	 * @class EtherTypeFilter
	 * A class for filtering by EtherType field of the Ethernet protocol. This enables to filter packets from certain
	 * protocols, such as ARP, IPv4, IPv6, VLAN tags, etc.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class EtherTypeFilter : public GeneralFilter
	{
	private:
		uint16_t ether_type_;

	public:
		/**
		 * A constructor that gets the EtherType and creates the filter with it
		 * @param[in] etherType The EtherType value to create the filter with
		 */
		explicit EtherTypeFilter(uint16_t etherType) : ether_type_(etherType)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the EtherType value
		 * @param[in] etherType The EtherType value to create the filter with
		 */
		void set_ether_type(uint16_t etherType)
		{
			ether_type_ = etherType;
		}
	};

	/**
	 * @class CompositeFilter
	 * The base class for all filter classes composed of several other filters. This class is virtual and abstract,
	 * hence cannot be instantiated.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class CompositeFilter : public GeneralFilter
	{
	protected:
		std::vector<GeneralFilter*> filter_list_;

	public:
		/**
		 * An empty constructor for this class. Use add_filter() to add filters to the composite filter.
		 */
		CompositeFilter() = default;

		/**
		 * A constructor that gets a list of pointers to filters and creates one filter from all filters
		 * @param[in] filters The list of pointers to filters
		 */
		explicit CompositeFilter(const std::vector<GeneralFilter*>& filters);

		/**
		 * Add filter to the composite filter
		 * @param[in] filter The filter to add
		 */
		void add_filter(GeneralFilter* filter)
		{
			filter_list_.push_back(filter);
		}

		/**
		 * Removes the first matching filter from the composite filter
		 * @param[in] filter The filter to remove
		 */
		void remove_filter(GeneralFilter* filter);

		/**
		 * Remove the current filters and set new ones
		 * @param[in] filters The new filters to set. The previous ones will be removed
		 */
		void set_filters(const std::vector<GeneralFilter*>& filters);

		/**
		 * Remove all filters from the composite filter.
		 */
		void clear_all_filters()
		{
			filter_list_.clear();
		}
	};

	/**
	 * Supported composite logic filter operators enum
	 */
	enum class CompositeLogicFilterOp
	{
		/** Logical AND operation */
		AND,
		/** Logical OR operation */
		OR,
	};

	namespace internal
	{
		/* Could potentially be moved into CompositeLogicFilter as a private member function, with if constexpr when
		 * C++17 is the minimum supported standard.*/
		/**
		 * Returns the delimiter for joining filter strings for the composite logic filter operation.
		 * @return A string literal to place between the different filter strings to produce a composite expression.
		 */
		template <CompositeLogicFilterOp op> constexpr const char* get_composite_logic_op_delimiter() = delete;
		template <> constexpr const char* get_composite_logic_op_delimiter<CompositeLogicFilterOp::AND>()
		{
			return " and ";
		};
		template <> constexpr const char* get_composite_logic_op_delimiter<CompositeLogicFilterOp::OR>()
		{
			return " or ";
		};
	}  // namespace internal

	/**
	 * @class CompositeLogicFilter
	 * A class for connecting several filters into one filter with logical operation between them.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	template <CompositeLogicFilterOp op> class CompositeLogicFilter : public CompositeFilter
	{
	public:
		using CompositeFilter::CompositeFilter;

		void parse_to_string(std::string& result) override
		{
			result.clear();
			for (auto it = filter_list_.cbegin(); it != filter_list_.cend(); ++it)
			{
				std::string innerFilter;
				(*it)->parse_to_string(innerFilter);
				result += '(' + innerFilter + ')';
				if (filter_list_.cend() - 1 != it)
				{
					result += internal::get_composite_logic_op_delimiter<op>();
				}
			}
		}
	};

	/**
	 * A class for connecting several filters into one filter with logical "and" between them. For example: if the 2
	 * filters are: "IPv4 address = x.x.x.x" + "TCP port dst = 80", then the new filter will be: "IPv4 address = x.x.x.x
	 * _AND_ TCP port dst = 80"
	 *
	 * This class follows the composite design pattern.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	using AndFilter = CompositeLogicFilter<CompositeLogicFilterOp::AND>;

	/**
	 * A class for connecting several filters into one filter with logical "or" between them. For example: if the 2
	 * filters are: "IPv4 address = x.x.x.x" + "TCP port dst = 80", then the new filter will be: "IPv4 address = x.x.x.x
	 * _OR_ TCP port dst = 80"
	 *
	 * This class follows the composite design pattern.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	using OrFilter = CompositeLogicFilter<CompositeLogicFilterOp::OR>;

	/**
	 * @class NotFilter
	 * A class for creating a filter which is inverse to another filter
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class NotFilter : public GeneralFilter
	{
	private:
		GeneralFilter* filter_to_inverse_;

	public:
		/**
		 * A constructor that gets a pointer to a filter and create the inverse version of it
		 * @param[in] filterToInverse A pointer to filter which the created filter be the inverse of
		 */
		explicit NotFilter(GeneralFilter* filterToInverse)
		{
			filter_to_inverse_ = filterToInverse;
		}

		void parse_to_string(std::string& result) override;

		/**
		 * Set a filter to create an inverse filter from
		 * @param[in] filterToInverse A pointer to filter which the created filter be the inverse of
		 */
		void set_filter(GeneralFilter* filterToInverse)
		{
			filter_to_inverse_ = filterToInverse;
		}
	};

	/**
	 * @class ProtoFilter
	 * A class for filtering traffic by protocol. Notice not all protocols are supported, only the following protocol
	 * are supported:
	 * ::TCP, ::UDP, ::ICMP, ::VLAN, ::IPv4, ::IPv6, ::ARP, ::Ethernet.
	 * In addition, the following protocol families are supported: ::GRE (distinguish between ::GREv0 and ::GREv1 is not
	 * supported),
	 * ::IGMP (distinguish between ::IGMPv1, ::IGMPv2 and ::IGMPv3 is not supported).
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class ProtoFilter : public GeneralFilter
	{
	private:
		ProtocolTypeFamily proto_family_;

	public:
		/**
		 * A constructor that gets a protocol and creates the filter
		 * @param[in] proto The protocol to filter, only packets matching this protocol will be received. Please note
		 * not all protocols are supported. List of supported protocols is found in the class description
		 */
		explicit ProtoFilter(ProtocolType proto) : proto_family_(proto)
		{}

		/**
		 * A constructor that gets a protocol family and creates the filter
		 * @param[in] protoFamily The protocol family to filter, only packets matching this protocol will be received.
		 * Please note not all protocols are supported. List of supported protocols is found in the class description
		 */
		explicit ProtoFilter(ProtocolTypeFamily protoFamily) : proto_family_(protoFamily)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the protocol to filter with
		 * @param[in] proto The protocol to filter, only packets matching this protocol will be received. Please note
		 * not all protocol families are supported. List of supported protocols is found in the class description
		 */
		void set_proto(ProtocolType proto)
		{
			proto_family_ = proto;
		}

		/**
		 * Set the protocol family to filter with
		 * @param[in] protoFamily The protocol family to filter, only packets matching this protocol will be received.
		 * Please note not all protocol families are supported. List of supported protocols is found in the class
		 * description
		 */
		void set_proto(ProtocolTypeFamily protoFamily)
		{
			proto_family_ = protoFamily;
		}
	};

	/**
	 * @class ArpFilter
	 * A class for filtering ARP packets according the ARP opcode. When using this filter only ARP packets with the
	 * relevant opcode will be received
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class ArpFilter : public GeneralFilter
	{
	private:
		ArpOpcode op_code_;

	public:
		/**
		 * A constructor that get the ARP opcode and creates the filter
		 * @param[in] opCode The ARP opcode: ::ARP_REQUEST or ::ARP_REPLY
		 */
		explicit ArpFilter(ArpOpcode opCode) : op_code_(opCode)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the ARP opcode
		 * @param[in] opCode The ARP opcode: ::ARP_REQUEST or ::ARP_REPLY
		 */
		void set_op_code(ArpOpcode opCode)
		{
			op_code_ = opCode;
		}
	};

	/**
	 * @class VlanFilter
	 * A class for filtering VLAN tagged packets by VLAN ID. When using this filter only packets tagged with VLAN which
	 * has the specific VLAN ID will be received
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class VlanFilter : public GeneralFilter
	{
	private:
		uint16_t vlan_id_;

	public:
		/**
		 * A constructor the gets the VLAN ID and creates the filter
		 * @param[in] vlanId The VLAN ID to use for the filter
		 */
		explicit VlanFilter(uint16_t vlanId) : vlan_id_(vlanId)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set the VLAN ID of the filter
		 * @param[in] vlanId The VLAN ID to use for the filter
		 */
		void set_vlan_id(uint16_t vlanId)
		{
			vlan_id_ = vlanId;
		}
	};

	/**
	 * @class TcpFlagsFilter
	 * A class for filtering only TCP packets which certain TCP flags are set in them
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class TcpFlagsFilter : public GeneralFilter
	{
	public:
		/**
		 * An enum of all TCP flags that can be use in the filter
		 */
		enum TcpFlags
		{
			/** TCP FIN flag */
			tcpFin = 1,
			/** TCP SYN flag */
			tcpSyn = 2,
			/** TCP RST flag */
			tcpRst = 4,
			/** TCP PSH flag */
			tcpPush = 8,
			/** TCP ACK flag */
			tcpAck = 16,
			/** TCP URG flag */
			tcpUrg = 32
		};

		/**
		 * An enum for representing 2 type of matches: match only packets that contain all flags defined in the filter
		 * or match packets that contain at least one of the flags defined in the filter
		 */
		enum MatchOptions
		{
			/** Match only packets that contain all flags defined in the filter */
			MatchAll,
			/** Match packets that contain at least one of the flags defined in the filter */
			MatchOneAtLeast
		};

	private:
		uint8_t tcp_flags_bit_mask_;
		MatchOptions match_option_;

	public:
		/**
		 * A constructor that gets a 1-byte bitmask containing all TCP flags participating in the filter and the match
		 * option, and creates the filter
		 * @param[in] tcpFlagBitMask A 1-byte bitmask containing all TCP flags participating in the filter. This
		 * parameter can contain the following value for example: TcpFlagsFilter::tcpSyn | TcpFlagsFilter::tcpAck |
		 * TcpFlagsFilter::tcpUrg
		 * @param[in] matchOption The match option: TcpFlagsFilter::MatchAll or TcpFlagsFilter::MatchOneAtLeast
		 */
		TcpFlagsFilter(uint8_t tcpFlagBitMask, MatchOptions matchOption)
		    : tcp_flags_bit_mask_(tcpFlagBitMask), match_option_(matchOption)
		{}

		/**
		 * Set the TCP flags and the match option
		 * @param[in] tcpFlagBitMask A 1-byte bitmask containing all TCP flags participating in the filter. This
		 * parameter can contain the following value for example: TcpFlagsFilter::tcpSyn | TcpFlagsFilter::tcpAck |
		 * TcpFlagsFilter::tcpUrg
		 * @param[in] matchOption The match option: TcpFlagsFilter::MatchAll or TcpFlagsFilter::MatchOneAtLeast
		 */
		void set_tcp_flags_bit_mask(uint8_t tcpFlagBitMask, MatchOptions matchOption)
		{
			tcp_flags_bit_mask_ = tcpFlagBitMask;
			match_option_ = matchOption;
		}

		void parse_to_string(std::string& result) override;
	};

	/**
	 * @class TcpWindowSizeFilter
	 * A class for filtering TCP packets that matches TCP window-size criteria.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class TcpWindowSizeFilter : public IFilterWithOperator
	{
	private:
		uint16_t window_size_;

	public:
		/**
		 * A constructor that get the window-size and operator and creates the filter. For example: "filter all TCP
		 * packets with window-size less than 1000"
		 * @param[in] windowSize The window-size value that will be used in the filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		TcpWindowSizeFilter(uint16_t windowSize, FilterOperator op) : IFilterWithOperator(op), window_size_(windowSize)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set window-size value
		 * @param[in] windowSize The window-size value that will be used in the filter
		 */
		void set_window_size(uint16_t windowSize)
		{
			window_size_ = windowSize;
		}
	};

	/**
	 * @class UdpLengthFilter
	 * A class for filtering UDP packets that matches UDP length criteria.
	 *
	 * For deeper understanding of the filter concept please refer to PcapFilter.h
	 */
	class UdpLengthFilter : public IFilterWithOperator
	{
	private:
		uint16_t length_;

	public:
		/**
		 * A constructor that get the UDP length and operator and creates the filter. For example: "filter all UDP
		 * packets with length greater or equal to 500"
		 * @param[in] length The length value that will be used in the filter
		 * @param[in] op The operator to use (e.g "equal", "greater than", etc.)
		 */
		UdpLengthFilter(uint16_t length, FilterOperator op) : IFilterWithOperator(op), length_(length)
		{}

		void parse_to_string(std::string& result) override;

		/**
		 * Set length value
		 * @param[in] length The length value that will be used in the filter
		 */
		void set_length(uint16_t length)
		{
			length_ = length;
		}
	};

}  // namespace vanhooks::net
// ---- end PcapFilter.h ----

// ---- begin Device.h ----
/// @file


/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/** A vector of pointers to RawPacket */
	typedef PointerVector<RawPacket> RawPacketVector;

	/**
	 * @class IDevice
	 * An abstract interface representing all packet processing devices. It stands as the root class for all devices.
	 * This is an abstract class that cannot be instantiated
	 */
	class IDevice
	{
	protected:
		bool device_opened_;

		// c'tor should not be public
		IDevice() : device_opened_(false)
		{}

	public:
		virtual ~IDevice()
		{}

		/**
		 * Open the device
		 * @return True if device was opened successfully, false otherwise
		 */
		virtual bool open() = 0;

		/**
		 * Close the device
		 */
		virtual void close() = 0;

		/**
		 * @return True if the file is opened, false otherwise
		 */
		inline bool is_opened()
		{
			return device_opened_;
		}
	};

	/**
	 * @class IFilterableDevice
	 * An abstract interface representing all devices that have BPF (Berkeley Packet Filter) filtering capabilities,
	 * meaning devices that can filter packets based on the BPF filtering syntax.
	 * This is an abstract class that cannot be instantiated
	 */
	class IFilterableDevice
	{
	protected:
		// c'tor should not be public
		IFilterableDevice()
		{}

	public:
		virtual ~IFilterableDevice()
		{}

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be
		 * received
		 * @param[in] filter The filter to be set in VanHooks' GeneralFilter format
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool set_filter(GeneralFilter& filter)
		{
			std::string filterAsString;
			filter.parse_to_string(filterAsString);
			return set_filter(filterAsString);
		}

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be
		 * received
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax
		 * (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool set_filter(std::string filterAsString) = 0;

		VH_DEPRECATED("use set_filter()")
		bool setFilter(GeneralFilter& filter) { return set_filter(filter); }
		VH_DEPRECATED("use set_filter()")
		bool setFilter(std::string filterAsString) { return set_filter(filterAsString); }

		/**
		 * Clear the filter currently set on the device
		 * @return True if filter was removed successfully or if no filter was set, false otherwise
		 */
		virtual bool clear_filter() = 0;
	};
}  // namespace vanhooks::net
// ---- end Device.h ----

// ---- begin PcapDevice.h ----
// forward declaration for the pcap descriptor defined in pcap.h
struct pcap;
typedef pcap pcap_t;
struct pcap_pkthdr;

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	// Forward Declaration - required for IPcapDevice::match_packet_with_filter
	class GeneralFilter;

	namespace internal
	{
		/**
		 * @class PcapHandle
		 * @brief A wrapper class for pcap_t* which is the libpcap packet capture descriptor.
		 * This class is used to manage the lifecycle of the pcap_t* object
		 */
		class PcapHandle
		{
		public:
			/**
			 * @brief Creates an empty handle.
			 */
			constexpr PcapHandle() noexcept = default;
			/**
			 * @brief Creates a handle from the provided pcap descriptor.
			 * @param pcapDescriptor The pcap descriptor to wrap.
			 */
			explicit PcapHandle(pcap_t* pcapDescriptor) noexcept;

			PcapHandle(const PcapHandle&) = delete;
			PcapHandle(PcapHandle&& other) noexcept;

			PcapHandle& operator=(const PcapHandle&) = delete;
			PcapHandle& operator=(PcapHandle&& other) noexcept;
			PcapHandle& operator=(std::nullptr_t) noexcept;

			~PcapHandle();

			/**
			 * @return True if the handle is not null, false otherwise.
			 */
			bool is_valid() const noexcept
			{
				return pcap_descriptor_ != nullptr;
			}

			/**
			 * @return The underlying pcap descriptor.
			 */
			pcap_t* get() const noexcept
			{
				return pcap_descriptor_;
			}

			/**
			 * @brief Releases ownership of the handle and returns the pcap descriptor.
			 * @return The pcap descriptor or nullptr if no handle is owned.
			 */
			pcap_t* release() noexcept;

			/**
			 * @brief Replaces the managed handle with the provided one.
			 * @param pcapDescriptor A new pcap descriptor to manage.
			 * @remarks If the handle contains a non-null descriptor it will be closed.
			 */
			void reset(pcap_t* pcapDescriptor = nullptr) noexcept;

			/**
			 * @brief Helper function to retrieve a view of the last error string for this handle.
			 * @return A null-terminated view of the last error string.
			 * @remarks The returned view is only valid until the next call to a pcap function.
			 */
			char const* get_last_error() const noexcept;

			/**
			 * @return True if the handle is not null, false otherwise.
			 */
			explicit operator bool() const noexcept
			{
				return is_valid();
			}

			bool operator==(std::nullptr_t) const noexcept
			{
				return !is_valid();
			}
			bool operator!=(std::nullptr_t) const noexcept
			{
				return is_valid();
			}

		private:
			pcap_t* pcap_descriptor_ = nullptr;
		};
	}  // namespace internal

	/**
	 * @class IPcapDevice
	 * An abstract class representing all libpcap-based packet capturing devices: files, libPcap, WinPcap/Npcap and
	 * RemoteCapture. This class is abstract and cannot be instantiated
	 */
	class IPcapDevice : public IDevice, public IFilterableDevice
	{
	protected:
		internal::PcapHandle pcap_descriptor_;

		// c'tor should not be public
		IPcapDevice() : IDevice()
		{}

	public:
		/**
		 * @struct PcapStats
		 * A container for pcap device statistics
		 */
		struct PcapStats
		{
			/** Number of packets received */
			uint64_t packetsRecv;
			/** Number of packets dropped */
			uint64_t packetsDrop;
			/** number of packets dropped by interface (not supported on all platforms) */
			uint64_t packetsDropByInterface;
		};

		virtual ~IPcapDevice();

		/**
		 * Get statistics from the device
		 * @param[out] stats An object containing the stats
		 */
		virtual void get_statistics(PcapStats& stats) const = 0;

		VH_DEPRECATED("use get_statistics()")
		void getStatistics(PcapStats& stats) const { get_statistics(stats); }

		/**
		 * A static method for retrieving pcap lib (libpcap/WinPcap/etc.) version information. This method is actually
		 * a wrapper for [pcap_lib_version()](https://www.tcpdump.org/manpages/pcap_lib_version.3pcap.html)
		 * @return A string containing the pcap lib version information
		 */
		static std::string get_pcap_lib_version_info();

		/**
		 * Match a raw packet with a given BPF filter. Notice this method is static which means you don't need any
		 * device instance in order to perform this match
		 * @param[in] filter A filter class to test against
		 * @param[in] rawPacket A pointer to the raw packet to match the filter with
		 * @return True if raw packet matches the filter or false otherwise
		 */
		static bool match_packet_with_filter(GeneralFilter& filter, RawPacket* rawPacket);

		// implement abstract methods

		using IFilterableDevice::set_filter;

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be
		 * received. Please note that when the device is closed the filter is reset so when reopening the device you
		 * need to call this method again in order to reactivate the filter
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax
		 * (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool set_filter(std::string filterAsString);

		/**
		 * Clear the filter currently set on device
		 * @return True if filter was removed successfully or if no filter was set, false otherwise
		 */
		bool clear_filter();
	};

}  // namespace vanhooks::net
// ---- end PcapDevice.h ----

// ---- begin PcapFileDevice.h ----
#include <fstream>

// forward declaration for structs and typedefs defined in pcap.h
struct pcap_dumper;
typedef struct pcap_dumper pcap_dumper_t;

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @enum FileTimestampPrecision
	 * An enumeration representing the precision of timestamps in a pcap file.
	 * The precision can be Unknown, Micro, or Nano.
	 */
	enum class FileTimestampPrecision : int8_t
	{
		/// Precision is unknown or not set/determined
		Unknown = -1,
		/// Precision is in microseconds.
		Microseconds = 0,
		/// Precision is in nanoseconds.
		Nanoseconds = 1
	};

	/**
	 * @class IFileDevice
	 * An abstract class (cannot be instantiated, has a private c'tor) which is the parent class for all file devices
	 */
	class IFileDevice : public IPcapDevice
	{
	protected:
		std::string file_name_;

		explicit IFileDevice(const std::string& fileName);
		virtual ~IFileDevice();

	public:
		/**
		 * @return The name of the file
		 */
		std::string get_file_name() const;

		// override methods

		/**
		 * Close the file
		 */
		void close() override;
	};

	/**
	 * @class IFileReaderDevice
	 * An abstract class (cannot be instantiated, has a private c'tor) which is the parent class for file reader devices
	 */
	class IFileReaderDevice : public IFileDevice
	{
	protected:
		uint32_t num_of_packets_read_;
		uint32_t num_of_packets_not_parsed_;

		/**
		 * A constructor for this class that gets the pcap full path file name to open. Notice that after calling this
		 * constructor the file isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		IFileReaderDevice(const std::string& fileName);

	public:
		/**
		 * A destructor for this class
		 */
		virtual ~IFileReaderDevice()
		{}

		/**
		 * @return The file size in bytes
		 */
		uint64_t get_file_size() const;

		virtual bool get_next_packet(RawPacket& rawPacket) = 0;

		VH_DEPRECATED("use get_next_packet()")
		bool getNextPacket(RawPacket& rawPacket) { return get_next_packet(rawPacket); }

		/**
		 * Read the next N packets into a raw packet vector
		 * @param[out] packetVec The raw packet vector to read packets into
		 * @param[in] numOfPacketsToRead Number of packets to read. If value <0 all remaining packets in the file will
		 * be read into the raw packet vector (this is the default value)
		 * @return The number of packets actually read
		 */
		int get_next_packets(RawPacketVector& packetVec, int numOfPacketsToRead = -1);

		/**
		 * A static method that creates an instance of the reader best fit to read the file. It decides by the file
		 * extension: for .pcapng files it returns an instance of VHPcapNgFileReaderDevice and for all other extensions it
		 * returns an instance of PcapFileReaderDevice
		 * @param[in] fileName The file name to open
		 * @return An instance of the reader to read the file. Notice you should free this instance when done using it
		 */
		static IFileReaderDevice* get_reader(const std::string& fileName);

		VH_DEPRECATED("use get_reader()")
		static IFileReaderDevice* getReader(const std::string& fileName) { return get_reader(fileName); }
	};

	/**
	 * @class PcapFileReaderDevice
	 * A class for opening a pcap file in read-only mode. This class enable to open the file and read all packets,
	 * packet-by-packet
	 */
	class PcapFileReaderDevice : public IFileReaderDevice
	{
	private:
		FileTimestampPrecision precision_;
		LinkLayerType pcap_link_layer_type_;

		// private copy c'tor
		PcapFileReaderDevice(const PcapFileReaderDevice& other);
		PcapFileReaderDevice& operator=(const PcapFileReaderDevice& other);

	public:
		/**
		 * A constructor for this class that gets the pcap full path file name to open. Notice that after calling this
		 * constructor the file isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		PcapFileReaderDevice(const std::string& fileName)
		    : IFileReaderDevice(fileName), precision_(FileTimestampPrecision::Unknown),
		      pcap_link_layer_type_(LINKTYPE_ETHERNET)
		{}

		/**
		 * A destructor for this class
		 */
		virtual ~PcapFileReaderDevice()
		{}

		/**
		 * @return The link layer type of this file
		 */
		LinkLayerType get_link_layer_type() const
		{
			return pcap_link_layer_type_;
		}

		/**
		 * @return The precision of the timestamps in the file. If the platform supports nanosecond precision, this
		 * method will return nanoseconds even if the file has microseconds since libpcap scales timestamps before
		 * supply. Otherwise, it will return microseconds.
		 */
		FileTimestampPrecision get_timestamp_precision() const
		{
			return precision_;
		}

		/**
		 * A static method that checks if nano-second precision is supported in the current platform and environment
		 * @return True if nano-second precision is supported, false otherwise
		 */
		static bool is_nano_second_precision_supported();

		// overridden methods

		/**
		 * Read the next packet from the file. Before using this method please verify the file is opened using open()
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an
		 * error log will be printed) or if reached end-of-file
		 */
		bool get_next_packet(RawPacket& rawPacket);

		/**
		 * Open the file name which path was specified in the constructor in a read-only mode
		 * @return True if file was opened successfully or if file is already opened. False if opening the file failed
		 * for some reason (for example: file path does not exist)
		 */
		bool open();

		/**
		 * Get statistics of packets read so far. In the PcapStats struct, only the packetsRecv member is relevant. The
		 * rest of the members will contain 0
		 * @param[out] stats The stats struct where stats are returned
		 */
		void get_statistics(PcapStats& stats) const;
	};

	/**
	 * @class SnoopFileReaderDevice
	 * A class for opening a snoop file in read-only mode. This class enable to open the file and read all packets,
	 * packet-by-packet
	 */
	class SnoopFileReaderDevice : public IFileReaderDevice
	{
	private:
#pragma pack(1)
		/*
		 * File format header.
		 */
		typedef struct
		{
			uint64_t identification_pattern;
			uint32_t version_number;
			uint32_t datalink_type;
		} snoop_file_header_t;

		/*
		 * Packet record header.
		 */
		typedef struct
		{
			uint32_t original_length;      /* original packet length */
			uint32_t included_length;      /* saved packet length */
			uint32_t packet_record_length; /* total record length */
			uint32_t ndrops_cumulative;    /* cumulative drops */
			uint32_t time_sec;             /* timestamp */
			uint32_t time_usec;            /* microsecond timestamp */
		} snoop_packet_header_t;
#pragma pack()

		LinkLayerType pcap_link_layer_type_;
		std::ifstream snoop_file_;

		// private copy c'tor
		SnoopFileReaderDevice(const PcapFileReaderDevice& other);
		SnoopFileReaderDevice& operator=(const PcapFileReaderDevice& other);

	public:
		/**
		 * A constructor for this class that gets the snoop full path file name to open. Notice that after calling this
		 * constructor the file isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		SnoopFileReaderDevice(const std::string& fileName)
		    : IFileReaderDevice(fileName), pcap_link_layer_type_(LINKTYPE_ETHERNET)
		{}

		/**
		 * A destructor for this class
		 */
		virtual ~SnoopFileReaderDevice();

		/**
		 * @return The link layer type of this file
		 */
		LinkLayerType get_link_layer_type() const
		{
			return pcap_link_layer_type_;
		}

		// overridden methods

		/**
		 * Read the next packet from the file. Before using this method please verify the file is opened using open()
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an
		 * error log will be printed) or if reached end-of-file
		 */
		bool get_next_packet(RawPacket& rawPacket);

		/**
		 * Open the file name which path was specified in the constructor in a read-only mode
		 * @return True if file was opened successfully or if file is already opened. False if opening the file failed
		 * for some reason (for example: file path does not exist)
		 */
		bool open();

		/**
		 * Get statistics of packets read so far. In the PcapStats struct, only the packetsRecv member is relevant. The
		 * rest of the members will contain 0
		 * @param[out] stats The stats struct where stats are returned
		 */
		void get_statistics(PcapStats& stats) const;

		/**
		 * Close the snoop file
		 */
		void close();
	};

	/**
	 * @class VHPcapNgFileReaderDevice
	 * A class for opening a pcap-ng file in read-only mode. This class enable to open the file and read all packets,
	 * packet-by-packet
	 */
	class VHPcapNgFileReaderDevice : public IFileReaderDevice
	{
	private:
		void* vh_pcap_ng_;
		BpfFilterWrapper bpf_wrapper_;

		// private copy c'tor
		VHPcapNgFileReaderDevice(const VHPcapNgFileReaderDevice& other);
		VHPcapNgFileReaderDevice& operator=(const VHPcapNgFileReaderDevice& other);

	public:
		/**
		 * A constructor for this class that gets the pcap-ng full path file name to open. Notice that after calling
		 * this constructor the file isn't opened yet, so reading packets will fail. For opening the file call open()
		 * @param[in] fileName The full path of the file to read
		 */
		VHPcapNgFileReaderDevice(const std::string& fileName);

		/**
		 * A destructor for this class
		 */
		virtual ~VHPcapNgFileReaderDevice()
		{
			close();
		}

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string
		 * specifying the operating system that was used for capturing the packets. This method reads this string from
		 * the metadata (if exists) and returns it
		 * @return The operating system string if exists, or an empty string otherwise
		 */
		std::string get_os() const;

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string
		 * specifying the hardware that was used for capturing the packets. This method reads this string from the
		 * metadata (if exists) and returns it
		 * @return The hardware string if exists, or an empty string otherwise
		 */
		std::string get_hardware() const;

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string
		 * specifying the capture application that was used for capturing the packets. This method reads this string
		 * from the metadata (if exists) and returns it
		 * @return The capture application string if exists, or an empty string otherwise
		 */
		std::string get_capture_application() const;

		/**
		 * The pcap-ng format allows storing metadata at the header of the file. Part of this metadata is a string
		 * containing a user-defined comment (can be any string). This method reads this string from the metadata (if
		 * exists) and returns it
		 * @return The comment written inside the file if exists, or an empty string otherwise
		 */
		std::string get_capture_file_comment() const;

		/**
		 * The pcap-ng format allows storing a user-defined comment for every packet (besides the comment per-file).
		 * This method reads the next packet and the comment attached to it (if such comment exists), and returns them
		 * both
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @param[out] packetComment The comment attached to the packet or an empty string if no comment exists
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an
		 * error log will be printed) or if reached end-of-file
		 */
		bool get_next_packet(RawPacket& rawPacket, std::string& packetComment);

		// overridden methods

		/**
		 * Read the next packet from the file. Before using this method please verify the file is opened using open()
		 * @param[out] rawPacket A reference for an empty RawPacket where the packet will be written
		 * @return True if a packet was read successfully. False will be returned if the file isn't opened (also, an
		 * error log will be printed) or if reached end-of-file
		 */
		bool get_next_packet(RawPacket& rawPacket);

		/**
		 * Open the file name which path was specified in the constructor in a read-only mode
		 * @return True if file was opened successfully or if file is already opened. False if opening the file failed
		 * for some reason (for example: file path does not exist)
		 */
		bool open();

		/**
		 * Get statistics of packets read so far.
		 * @param[out] stats The stats struct where stats are returned
		 */
		void get_statistics(PcapStats& stats) const;

		/**
		 * Set a filter for PcapNG reader device. Only packets that match the filter will be received
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax
		 * (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		bool set_filter(std::string filterAsString);

		/**
		 * Close the pacp-ng file
		 */
		void close();
	};

	/**
	 * @class IFileWriterDevice
	 * An abstract class (cannot be instantiated, has a private c'tor) which is the parent class for file writer devices
	 */
	class IFileWriterDevice : public IFileDevice
	{
	protected:
		uint32_t num_of_packets_written_;
		uint32_t num_of_packets_not_written_;

		IFileWriterDevice(const std::string& fileName);

	public:
		/**
		 * A destructor for this class
		 */
		virtual ~IFileWriterDevice()
		{}

		virtual bool write_packet(RawPacket const& packet) = 0;

		VH_DEPRECATED("use write_packet()")
		bool writePacket(RawPacket const& packet) { return write_packet(packet); }

		virtual bool write_packets(const RawPacketVector& packets) = 0;

		using IFileDevice::open;
		virtual bool open(bool appendMode) = 0;
	};

	/**
	 * @class PcapFileWriterDevice
	 * A class for opening a pcap file for writing or create a new pcap file and write packets to it. This class adds
	 * a unique capability that isn't supported in WinPcap and in older libpcap versions which is to open a pcap file
	 * in append mode where packets are written at the end of the pcap file instead of running it over
	 */
	class PcapFileWriterDevice : public IFileWriterDevice
	{
	private:
		pcap_dumper_t* pcap_dump_handler_;
		LinkLayerType pcap_link_layer_type_;
		bool append_mode_;
		FileTimestampPrecision precision_;
		FILE* file_;

		// private copy c'tor
		PcapFileWriterDevice(const PcapFileWriterDevice& other);
		PcapFileWriterDevice& operator=(const PcapFileWriterDevice& other);

		void close_file();

	public:
		/**
		 * A constructor for this class that gets the pcap full path file name to open for writing or create. Notice
		 * that after calling this constructor the file isn't opened yet, so writing packets will fail. For opening the
		 * file call open()
		 * @param[in] fileName The full path of the file
		 * @param[in] linkLayerType The link layer type all packet in this file will be based on. The default is
		 * Ethernet
		 * @param[in] nanosecondsPrecision A boolean indicating whether to write timestamps in nano-precision. If set to
		 * false, timestamps will be written in micro-precision
		 */
		PcapFileWriterDevice(const std::string& fileName, LinkLayerType linkLayerType = LINKTYPE_ETHERNET,
		                     bool nanosecondsPrecision = false);

		/**
		 * A destructor for this class
		 */
		~PcapFileWriterDevice()
		{}

		/**
		 * Write a RawPacket to the file. Before using this method please verify the file is opened using open(). This
		 * method won't change the written packet
		 * @param[in] packet A reference for an existing RawPcket to write to the file
		 * @return True if a packet was written successfully. False will be returned if the file isn't opened
		 * or if the packet link layer type is different than the one defined for the file
		 * (in all cases, an error will be printed to log)
		 */
		bool write_packet(RawPacket const& packet) override;

		/**
		 * Write multiple RawPacket to the file. Before using this method please verify the file is opened using open().
		 * This method won't change the written packets or the RawPacketVector instance
		 * @param[in] packets A reference for an existing RawPcketVector, all of its packets will be written to the file
		 * @return True if all packets were written successfully to the file. False will be returned if the file isn't
		 * opened (also, an error log will be printed) or if at least one of the packets wasn't written successfully to
		 * the file
		 */
		bool write_packets(const RawPacketVector& packets) override;

		/**
		 * @return The precision of the timestamps in the file.
		 */
		FileTimestampPrecision get_timestamp_precision() const
		{
			return precision_;
		}

		/**
		 * A static method that checks if nano-second precision is supported in the current platform and environment
		 * @return True if nano-second precision is supported, false otherwise
		 */
		static bool is_nano_second_precision_supported();

		// override methods

		/**
		 * Open the file in a write mode. If file doesn't exist, it will be created. If it does exist it will be
		 * overwritten, meaning all its current content will be deleted
		 * @return True if file was opened/created successfully or if file is already opened. False if opening the file
		 * failed for some reason (an error will be printed to log)
		 */
		bool open() override;

		/**
		 * Same as open(), but enables to open the file in append mode in which packets will be appended to the file
		 * instead of overwrite its current content. In append mode file must exist, otherwise opening will fail
		 * @param[in] appendMode A boolean indicating whether to open the file in append mode or not. If set to false
		 * this method will act exactly like open(). If set to true, file will be opened in append mode
		 * @return True of managed to open the file successfully. In case appendMode is set to true, false will be
		 * returned if file wasn't found or couldn't be read, if file type is not pcap, or if link type specified in
		 * c'tor is different from current file link type. In case appendMode is set to false, please refer to open()
		 * for return values
		 */
		bool open(bool appendMode) override;

		/**
		 * Flush and close the pacp file
		 */
		void close() override;

		/**
		 * Flush packets to disk.
		 */
		void flush();

		/**
		 * Get statistics of packets written so far.
		 * @param[out] stats The stats struct where stats are returned
		 */
		void get_statistics(PcapStats& stats) const override;
	};

	/**
	 * @class VHPcapNgFileWriterDevice
	 * A class for opening a pcap-ng file for writing or creating a new pcap-ng file and write packets to it. This class
	 * adds unique capabilities such as writing metadata attributes into the file header, adding comments per packet and
	 * opening the file in append mode where packets are added to a file instead of overriding it. This capabilities are
	 * part of the pcap-ng standard but aren't supported in most tools and libraries
	 */
	class VHPcapNgFileWriterDevice : public IFileWriterDevice
	{
	private:
		void* vh_pcap_ng_;
		int compression_level_;
		BpfFilterWrapper bpf_wrapper_;

		// private copy c'tor
		VHPcapNgFileWriterDevice(const PcapFileWriterDevice& other);
		VHPcapNgFileWriterDevice& operator=(const VHPcapNgFileWriterDevice& other);

	public:
		/**
		 * A constructor for this class that gets the pcap-ng full path file name to open for writing or create. Notice
		 * that after calling this constructor the file isn't opened yet, so writing packets will fail. For opening the
		 * file call open()
		 * @param[in] fileName The full path of the file
		 * @param[in] compressionLevel The compression level to use when writing the file, use 0 to disable compression
		 * or 10 for max compression. Default is 0
		 */
		VHPcapNgFileWriterDevice(const std::string& fileName, int compressionLevel = 0);

		/**
		 * A destructor for this class
		 */
		virtual ~VHPcapNgFileWriterDevice()
		{
			close();
		}

		/**
		 * Open the file in a write mode. If file doesn't exist, it will be created. If it does exist it will be
		 * overwritten, meaning all its current content will be deleted. As opposed to open(), this method also allows
		 * writing several metadata attributes that will be stored in the header of the file
		 * @param[in] os A string describing the operating system that was used to capture the packets. If this string
		 * is empty or null it will be ignored
		 * @param[in] hardware A string describing the hardware that was used to capture the packets. If this string is
		 * empty or null it will be ignored
		 * @param[in] captureApp A string describing the application that was used to capture the packets. If this
		 * string is empty or null it will be ignored
		 * @param[in] fileComment A string containing a user-defined comment that will be part of the metadata of the
		 * file. If this string is empty or null it will be ignored
		 * @return True if file was opened/created successfully or if file is already opened. False if opening the file
		 * failed for some reason (an error will be printed to log)
		 */
		bool open(const std::string& os, const std::string& hardware, const std::string& captureApp,
		          const std::string& fileComment);

		/**
		 * The pcap-ng format allows adding a user-defined comment for each stored packet. This method writes a
		 * RawPacket to the file and adds a comment to it. Before using this method please verify the file is opened
		 * using open(). This method won't change the written packet or the input comment
		 * @param[in] packet A reference for an existing RawPcket to write to the file
		 * @param[in] comment The comment to be written for the packet. If this string is empty or null it will be
		 * ignored
		 * @return True if a packet was written successfully. False will be returned if the file isn't opened (an error
		 * will be printed to log)
		 */
		bool write_packet(RawPacket const& packet, const std::string& comment);

		// overridden methods

		/**
		 * Write a RawPacket to the file. Before using this method please verify the file is opened using open(). This
		 * method won't change the written packet
		 * @param[in] packet A reference for an existing RawPcket to write to the file
		 * @return True if a packet was written successfully. False will be returned if the file isn't opened (an error
		 * will be printed to log)
		 */
		bool write_packet(RawPacket const& packet);

		/**
		 * Write multiple RawPacket to the file. Before using this method please verify the file is opened using open().
		 * This method won't change the written packets or the RawPacketVector instance
		 * @param[in] packets A reference for an existing RawPcketVector, all of its packets will be written to the file
		 * @return True if all packets were written successfully to the file. False will be returned if the file isn't
		 * opened (also, an error log will be printed) or if at least one of the packets wasn't written successfully to
		 * the file
		 */
		bool write_packets(const RawPacketVector& packets);

		/**
		 * Open the file in a write mode. If file doesn't exist, it will be created. If it does exist it will be
		 * overwritten, meaning all its current content will be deleted
		 * @return True if file was opened/created successfully or if file is already opened. False if opening the file
		 * failed for some reason (an error will be printed to log)
		 */
		bool open();

		/**
		 * Same as open(), but enables to open the file in append mode in which packets will be appended to the file
		 * instead of overwrite its current content. In append mode file must exist, otherwise opening will fail
		 * @param[in] appendMode A boolean indicating whether to open the file in append mode or not. If set to false
		 * this method will act exactly like open(). If set to true, file will be opened in append mode
		 * @return True of managed to open the file successfully. In case appendMode is set to true, false will be
		 * returned if file wasn't found or couldn't be read, if file type is not pcap-ng. In case appendMode is set to
		 * false, please refer to open() for return values
		 */
		bool open(bool appendMode);

		/**
		 * Flush packets to the pcap-ng file
		 */
		void flush();

		/**
		 * Flush and close the pcap-ng file
		 */
		void close();

		/**
		 * Get statistics of packets written so far.
		 * @param[out] stats The stats struct where stats are returned
		 */
		void get_statistics(PcapStats& stats) const;

		/**
		 * Set a filter for PcapNG writer device. Only packets that match the filter will be persisted
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax
		 * (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		bool set_filter(std::string filterAsString);
	};

}  // namespace vanhooks::net
// ---- end PcapFileDevice.h ----

// ---- begin PcapLiveDevice.h ----
#include <atomic>
#include <vector>
#include <string.h>
#include <thread>
#include <functional>


// forward declarations for structs and typedefs that are defined in pcap.h
struct pcap_if;
typedef pcap_if pcap_if_t;
struct pcap_addr;
typedef struct pcap_addr pcap_addr_t;

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	class PcapLiveDevice;

	/**
	 * A callback that is called when a packet is captured by PcapLiveDevice
	 * @param[in] packet A pointer to the raw packet
	 * @param[in] device A pointer to the PcapLiveDevice instance
	 * @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	 */
	using OnPacketArrivesCallback = std::function<void(RawPacket*, PcapLiveDevice*, void*)>;

	/**
	 * A callback that is called when a packet is captured by PcapLiveDevice
	 * @param[in] packet A pointer to the raw packet
	 * @param[in] device A pointer to the PcapLiveDevice instance
	 * @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	 * @return True when main thread should stop blocking or false otherwise
	 */
	using OnPacketArrivesStopBlocking = std::function<bool(RawPacket*, PcapLiveDevice*, void*)>;

	/**
	 * A callback that is called periodically for stats collection if user asked to start packet capturing with periodic
	 * stats collection
	 * @param[in] stats A reference to the most updated stats
	 * @param[in] userCookie A pointer to the object put by the user when packet capturing stared
	 */
	using OnStatsUpdateCallback = std::function<void(IPcapDevice::PcapStats&, void*)>;

	/**
	 * @class PcapLiveDevice
	 * A class that wraps a network interface (each of the interfaces listed in ifconfig/ipconfig).
	 * This class wraps the libpcap capabilities of capturing packets from the network, filtering packets and sending
	 * packets back to the network. This class is relevant for Linux applications only. On Windows the WinPcapLiveDevice
	 * (which inherits this class) is used. Both classes are almost similar in capabilities, the main difference between
	 * them is adapting some capabilities to the specific OS. This class cannot be instantiated by the user (it has a
	 * private constructor), as network interfaces aren't dynamic. Instances of this class (one instance per network
	 * interface) are created by PcapLiveDeviceList singleton on application startup and the user can get access to them
	 * by using PcapLiveDeviceList public methods such as PcapLiveDeviceList#get_pcap_live_device_by_ip()<BR> Main
	 * capabilities of this class:
	 * - Get all available information for this network interfaces such as name, IP addresses, MAC address, MTU, etc.
	 *   This information is taken from both libpcap and the OS
	 * - Capture packets from the network. Capturing is always conducted on a different thread. VanHooks creates
	 *   this thread when capturing starts and kills it when capturing ends. This prevents the application from being
	 *   stuck while waiting for packets or processing them. Currently only one capturing thread is allowed, so when the
	 *   interface is in capture mode, no further capturing is allowed. In addition to capturing the user can get stats
	 *   on packets that were received by the application, dropped by the NIC (due to full NIC buffers), etc. Stats
	 *   collection can be initiated by the user by calling get_statistics() or be pushed to the user periodically by
	 *   supplying a callback and a timeout to start_capture()
	 * - Send packets back to the network. Sending the packets is done on the caller thread. No additional threads are
	 *   created for this task
	 */
	class PcapLiveDevice : public IPcapDevice
	{
		friend class PcapLiveDeviceList;

	protected:
		// This is a second descriptor for the same device. It is needed because of a bug
		// that occurs in libpcap on Linux (on Windows using WinPcap/Npcap it works well):
		// It's impossible to capture packets sent by the same descriptor
		pcap_t* pcap_send_descriptor_;
		int pcap_selectable_fd_;
		std::string name_;
		std::string description_;
		bool is_loopback_;
		uint32_t device_mtu_;
		std::vector<pcap_addr_t> addresses_;
		MacAddress mac_address_;
		IPv4Address default_gateway_;
		std::thread capture_thread_;
		std::thread stats_thread_;
		bool stats_thread_started_;

		// Should be set to true by the Caller for the Callee
		std::atomic<bool> stop_thread_;
		// Should be set to true by the Callee for the Caller
		std::atomic<bool> capture_thread_started_;

		OnPacketArrivesCallback cb_on_packet_arrives_;
		void* cb_on_packet_arrives_user_cookie_;
		OnStatsUpdateCallback cb_on_stats_update_;
		void* cb_on_stats_update_user_cookie_;
		OnPacketArrivesStopBlocking cb_on_packet_arrives_blocking_mode_;
		void* cb_on_packet_arrives_blocking_mode_user_cookie_;
		int interval_to_update_stats_;
		RawPacketVector* captured_packets_;
		bool capture_callback_mode_;
		LinkLayerType link_type_;
		bool use_poll_;

		// c'tor is not public, there should be only one for every interface (created by PcapLiveDeviceList)
		PcapLiveDevice(pcap_if_t* pInterface, bool calculateMTU, bool calculateMacAddress,
		               bool calculateDefaultGateway);
		// copy c'tor is not public
		PcapLiveDevice(const PcapLiveDevice& other);
		PcapLiveDevice& operator=(const PcapLiveDevice& other);

		void set_device_mtu();
		void set_device_mac_address();
		void set_default_gateway();

		// threads
		void capture_thread_main();
		void stats_thread_main();

		static void on_packet_arrives(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);
		static void on_packet_arrives_no_callback(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);
		static void on_packet_arrives_blocking_mode(uint8_t* user, const struct pcap_pkthdr* pkthdr, const uint8_t* packet);

	public:
		/**
		 * The type of the live device
		 */
		enum LiveDeviceType
		{
			/** libPcap live device */
			LibPcapDevice,
			/** WinPcap/Npcap live device */
			WinPcapDevice,
			/** WinPcap/Npcap Remote Capture device */
			RemoteDevice
		};

		/**
		 * Device capturing mode
		 */
		enum DeviceMode
		{
			/** Only packets that their destination is this NIC are captured */
			Normal = 0,
			/** All packets that arrive to the NIC are captured, even packets that their destination isn't this NIC */
			Promiscuous = 1
		};

		/**
		 * Set direction for capturing packets (you can read more here:
		 * <https://www.tcpdump.org/manpages/pcap.3pcap.html#lbAI>)
		 */
		enum PcapDirection
		{
			/** Capture traffics both incoming and outgoing */
			VH_INOUT = 0,
			/** Only capture incoming traffics */
			VH_IN,
			/** Only capture outgoing traffics */
			VH_OUT
		};

		/**
		 * @struct DeviceConfiguration
		 * A struct that contains user configurable parameters for opening a device. All parameters have default values
		 * so the user isn't expected to set all parameters or understand exactly how they work
		 */
		struct DeviceConfiguration
		{
			/** Indicates whether to open the device in promiscuous or normal mode */
			DeviceMode mode;

			/** Set the packet buffer timeout in milliseconds. You can read more here:
			 * https://www.tcpdump.org/manpages/pcap.3pcap.html .
			 * Any value above 0 is considered legal, otherwise a value of 1 or -1 is used (depends on the platform)
			 */
			int packetBufferTimeoutMs;

			/**
			 * Set the packet buffer size. You can read more about the packet buffer here:
			 * https://www.tcpdump.org/manpages/pcap.3pcap.html .
			 * Any value of 100 or above is considered valid, otherwise the default value is used (which varies between
			 * different OS's). However, please notice that setting values which are too low or two high may result in
			 * failure to open the device. These too low or too high thresholds may vary between OS's, as an example
			 * please refer to this thread: https://stackoverflow.com/questions/11397367/issue-in-pcap-set-buffer-size
			 */
			int packetBufferSize;

			/**
			 * Set the direction for capturing packets. You can read more here:
			 * <https://www.tcpdump.org/manpages/pcap.3pcap.html#lbAI>.
			 */
			PcapDirection direction;

			/**
			 * Set the snapshot length. Snapshot length is the amount of data for each frame that is actually captured.
			 * Note that taking larger snapshots both increases the amount of time it takes to process packets and,
			 * effectively, decreases the amount of packet buffering. This may cause packets to be lost. Note also that
			 * taking smaller snapshots will discard data from protocols above the transport layer, which loses
			 * information that may be important. You can read more here: https://wiki.wireshark.org/SnapLen
			 */
			int snapshotLength;

			/**
			 * Set NFLOG group. Which NFLOG group to be listened to when connecting to NFLOG device. If device is not of
			 * type NFLOG this attribute is ignored.
			 */
			unsigned int nflogGroup;

			/// In Unix-like system, use poll() for blocking mode.
			bool usePoll;

			/**
			 * A c'tor for this struct
			 * @param[in] mode The mode to open the device: promiscuous or non-promiscuous. Default value is promiscuous
			 * @param[in] packetBufferTimeoutMs Buffer timeout in millisecond. Default value is 0 which means set
			 * timeout of 1 or -1 (depends on the platform)
			 * @param[in] packetBufferSize The packet buffer size. Default value is 0 which means use the default value
			 * (varies between different OS's)
			 * @param[in] direction Direction for capturing packets. Default value is INOUT which means capture both
			 * incoming and outgoing packets (not all platforms support this)
			 * @param[in] snapshotLength Snapshot length for capturing packets. Default value is 0 which means use the
			 * default value. A snapshot length of 262144 should be big enough for maximum-size Linux loopback packets
			 * (65549) and some USB packets captured with USBPcap (> 131072, < 262144). A snapshot length of 65535
			 * should be sufficient, on most if not all networks, to capture all the data available from the packet.
			 * @param[in] nflogGroup NFLOG group for NFLOG devices. Default value is 0.
			 * @param[in] usePoll use `poll()` when capturing packets in blocking more (`start_capture_blocking_mode()`) on
			 * Unix-like system. Default value is false.
			 */
			explicit DeviceConfiguration(DeviceMode mode = Promiscuous, int packetBufferTimeoutMs = 0,
			                             int packetBufferSize = 0, PcapDirection direction = VH_INOUT,
			                             int snapshotLength = 0, unsigned int nflogGroup = 0, bool usePoll = false)
			{
				this->mode = mode;
				this->packetBufferTimeoutMs = packetBufferTimeoutMs;
				this->packetBufferSize = packetBufferSize;
				this->direction = direction;
				this->snapshotLength = snapshotLength;
				this->nflogGroup = nflogGroup;
				this->usePoll = usePoll;
			}
		};

		/**
		 * A destructor for this class
		 */
		~PcapLiveDevice() override;

		/**
		 * @return The type of the device (libPcap, WinPcap/Npcap or a remote device)
		 */
		virtual LiveDeviceType get_device_type() const
		{
			return LibPcapDevice;
		}

		/**
		 * @return The name of the device (e.g eth0), taken from pcap_if_t->name
		 */
		std::string get_name() const
		{
			return name_;
		}

		VH_DEPRECATED("use get_name()")
		std::string getName() const { return get_name(); }

		/**
		 * @return A human-readable description of the device, taken from pcap_if_t->description. May be empty string in
		 * some interfaces
		 */
		std::string get_desc() const
		{
			return description_;
		}

		VH_DEPRECATED("use get_desc()")
		std::string getDesc() const { return get_desc(); }

		/**
		 * @return True if this interface is a loopback interface, false otherwise
		 */
		bool get_loopback() const
		{
			return is_loopback_;
		}

		VH_DEPRECATED("use get_loopback()")
		bool getLoopback() const { return get_loopback(); }

		/**
		 * @return The device's maximum transmission unit (MTU) in bytes
		 */
		virtual uint32_t get_mtu() const
		{
			return device_mtu_;
		}

		/**
		 * @return The device's link layer type
		 */
		virtual LinkLayerType get_link_type() const
		{
			return link_type_;
		}

		/**
		 * @return A vector containing all addresses defined for this interface, each in pcap_addr_t struct
		 * @deprecated This method is deprecated and will be removed in future versions. Please use get_ip_addresses()
		 * instead.
		 */
		// clang-format off
		// Breaking the macro into multiple lines causes doxygen to cause a fit.
		VH_DEPRECATED("This method is deprecated and will be removed in future versions. Please use get_ip_addresses() instead.")
		// clang-format on
		const std::vector<pcap_addr_t>& get_addresses() const
		{
			return addresses_;
		}

		/**
		 * @return A vector containing all IP addresses defined for this interface.
		 */
		std::vector<IPAddress> get_ip_addresses() const;

		VH_DEPRECATED("use get_ip_addresses()")
		std::vector<IPAddress> getIPAddresses() const { return get_ip_addresses(); }

		/**
		 * @return The MAC address for this interface
		 */
		virtual MacAddress get_mac_address() const
		{
			return mac_address_;
		}

		/**
		 * @return The IPv4 address for this interface. If multiple IPv4 addresses are defined for this interface, the
		 * first will be picked. If no IPv4 addresses are defined, a zeroed IPv4 address (IPv4Address#Zero) will be
		 * returned
		 */
		IPv4Address get_ipv4_address() const;

		/**
		 * @return The IPv6 address for this interface. If multiple IPv6 addresses are defined for this interface, the
		 * first will be picked. If no IPv6 addresses are defined, a zeroed IPv6 address (IPv6Address#Zero) will be
		 * returned
		 */
		IPv6Address get_ipv6_address() const;

		/**
		 * @return The default gateway defined for this interface. If no default gateway is defined, if it's not IPv4 or
		 * if couldn't extract default gateway IPv4Address#Zero will be returned. If multiple gateways were defined the
		 * first one will be returned
		 */
		IPv4Address get_default_gateway() const;

		/**
		 * @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers
		 * were defined or they couldn't be extracted from some reason. This list is created in PcapLiveDeviceList class
		 * and can be also retrieved from there. This method exists for convenience - so it'll be possible to get this
		 * list from PcapLiveDevice as well
		 */
		const std::vector<IPv4Address>& get_dns_servers() const;

		/**
		 * Start capturing packets on this network interface (device). Each time a packet is captured the
		 * on_packet_arrives callback is called. The capture is done on a new thread created by this method, meaning all
		 * callback calls are done in a thread other than the caller thread. Capture process will stop and this capture
		 * thread will be terminated when calling stop_capture(). This method must be called after the device is opened
		 * (i.e the open() method was called), otherwise an error will be returned.
		 * @param[in] on_packet_arrives A callback that is called each time a packet is captured
		 * @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to
		 * the on_packet_arrives callback each time it is called. This cookie is very useful for transferring objects that
		 * give context to the capture callback, for example: objects that counts packets, manages flow state or manages
		 * the application state according to the packet that was captured
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Capture thread could not be created
		 */
		virtual bool start_capture(OnPacketArrivesCallback on_packet_arrives, void* onPacketArrivesUserCookie);

		VH_DEPRECATED("use start_capture()")
		bool startCapture(OnPacketArrivesCallback on_packet_arrives, void* onPacketArrivesUserCookie)
		{
			return start_capture(on_packet_arrives, onPacketArrivesUserCookie);
		}

		/**
		 * Start capturing packets on this network interface (device) with periodic stats collection. Each time a packet
		 * is captured the on_packet_arrives callback is called. In addition, each intervalInSecondsToUpdateStats seconds
		 * stats are collected from the device and the onStatsUpdate callback is called. Both the capture and periodic
		 * stats collection are done on new threads created by this method, each on a different thread, meaning all
		 * callback calls are done in threads other than the caller thread. Capture process and stats collection will
		 * stop and threads will be terminated when calling stop_capture(). This method must be called after the device
		 * is opened (i.e the open() method was called), otherwise an error will be returned.
		 * @param[in] on_packet_arrives A callback that is called each time a packet is captured
		 * @param[in] onPacketArrivesUserCookie A pointer to a user provided object. This object will be transferred to
		 * the on_packet_arrives callback each time it is called. This cookie is very useful for transferring objects that
		 * give context to the capture callback, for example: objects that counts packets, manages flow state or manages
		 * the application state according to the packet that was captured
		 * @param[in] intervalInSecondsToUpdateStats The interval in seconds to activate periodic stats collection
		 * @param[in] onStatsUpdate A callback that will be called each time intervalInSecondsToUpdateStats expires and
		 * stats are collected. This callback will contain the collected stats
		 * @param[in] onStatsUpdateUserCookie A pointer to a user provided object. This object will be transferred to
		 * the onStatsUpdate callback each time it is called
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Capture thread could not be created
		 * - Stats collection thread could not be created
		 */
		virtual bool start_capture(OnPacketArrivesCallback on_packet_arrives, void* onPacketArrivesUserCookie,
		                          int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
		                          void* onStatsUpdateUserCookie);

		/**
		 * Start capturing packets on this network interface (device) with periodic stats collection only. This means
		 * that packets arriving to the network interface aren't delivered to the user but only counted. Each
		 * intervalInSecondsToUpdateStats seconds stats are collected from the device and the onStatsUpdate callback is
		 * called with the updated counters. The periodic stats collection is done on a new thread created by this
		 * method, meaning all callback calls are done in threads other than the caller thread. Stats collection will
		 * stop and threads will be terminated when calling stop_capture(). This method must be called after the device
		 * is opened (i.e the open() method was called), otherwise an error will be returned.
		 * @param[in] intervalInSecondsToUpdateStats The interval in seconds to activate periodic stats collection
		 * @param[in] onStatsUpdate A callback that will be called each time intervalInSecondsToUpdateStats expires and
		 * stats are collected. This callback will contain the collected stats
		 * @param[in] onStatsUpdateUserCookie A pointer to a user provided object. This object will be transferred to
		 * the onStatsUpdate callback each time it is called
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Stats collection thread could not be created
		 */
		virtual bool start_capture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
		                          void* onStatsUpdateUserCookie);

		/**
		 * Start capturing packets on this network interface (device). All captured packets are added to
		 * capturedPacketsVector, so at the end of the capture (when calling stop_capture()) this vector contains
		 * pointers to all captured packets in the form of RawPacket. The capture is done on a new thread created by
		 * this method, meaning capturedPacketsVector is updated from another thread other than the caller thread (so
		 * user should avoid changing or iterating this vector while capture is on). Capture process will stop and this
		 * capture thread will be terminated when calling stop_capture(). This method must be called after the device is
		 * opened (i.e the open() method was called), otherwise an error will be returned.
		 * @param[in] capturedPacketsVector A reference to a RawPacketVector, meaning a vector of pointer to RawPacket
		 * objects
		 * @return True if capture started successfully, false if (relevant log error is printed in any case):
		 * - Capture is already running
		 * - Device is not opened
		 * - Capture thread could not be created
		 */
		virtual bool start_capture(RawPacketVector& capturedPacketsVector);

		/**
		 * Start capturing packets on this network interface (device) in blocking mode, meaning this method blocks and
		 * won't return until the user frees the blocking (via on_packet_arrives callback) or until a user defined timeout
		 * expires. Whenever a packets is captured the on_packet_arrives callback is called and lets the user handle the
		 * packet. In each callback call the user should return true if he wants to release the block or false if it
		 * wants it to keep blocking. Regardless of this callback a timeout is defined when start capturing. When this
		 * timeout expires the method will return.<BR> Please notice that stop_capture() isn't needed here because when
		 * the method returns (after timeout or per user decision) capturing on the device is stopped
		 * @param[in] on_packet_arrives A callback given by the user for handling incoming packets. After handling each
		 * packet the user needs to return a boolean value. True value indicates stop capturing and stop blocking and
		 * false value indicates continue capturing and blocking
		 * @param[in] userCookie A pointer to a user provided object. This object will be transferred to the
		 * on_packet_arrives callback each time it is called. This cookie is very useful for transferring objects that
		 * give context to the capture callback, for example: objects that counts packets, manages flow state or manages
		 * the application state according to the packet that was captured
		 * @param[in] timeout A timeout in seconds for the blocking to stop even if the user didn't return "true" in the
		 * on_packet_arrives callback. The precision of `timeout` is millisecond, e.g. 2.345 seconds means 2345
		 * milliseconds. If this timeout is set to 0 or less the timeout will be ignored, meaning the method will keep
		 * handling packets until the `on_packet_arrives` callback returns `true`.
		 * @return -1 if timeout expired, 1 if blocking was stopped via on_packet_arrives callback or 0 if an error
		 * occurred (such as device not open etc.). When returning 0 an appropriate error message is printed to log
		 * @note On Unix-like systems, enabling the `usePoll` option in `DeviceConfiguration` prevents the method from
		 * blocking indefinitely when no packets are available, even if a timeout is set.
		 */
		virtual int start_capture_blocking_mode(OnPacketArrivesStopBlocking on_packet_arrives, void* userCookie,
		                                     const double timeout);

		/**
		 * Stop a currently running packet capture. This method terminates gracefully both packet capture thread and
		 * periodic stats collection thread (both if exist)
		 */
		void stop_capture();

		VH_DEPRECATED("use stop_capture()")
		void stopCapture() { stop_capture(); }

		/**
		 * Check if a capture thread is running
		 * @return True if a capture thread is currently running
		 */
		bool capture_active();

		/**
		 * Checks whether the packetPayloadLength is larger than the device MTU. Logs an error if check fails
		 * @param[in] packetPayloadLength The length of the IP layer of the packet
		 * @return True if the packetPayloadLength is less than or equal to the device MTU
		 */
		bool do_mtu_check(int packetPayloadLength) const;

		/**
		 * Send a RawPacket to the network
		 * @param[in] rawPacket A reference to the raw packet to send. This method treats the raw packet as read-only,
		 * it doesn't change anything in it
		 * @param[in] checkMtu Whether the length of the packet's payload should be checked against the MTU. If enabled
		 * this comes with a small performance penalty. Default value is false to avoid performance overhead. Set to
		 * true if you don't know whether packets fit the live device's MTU and you can afford the overhead.
		 * @return True if packet was sent successfully. False will be returned in the following cases (relevant log
		 * error is printed in any case):
		 * - Device is not opened
		 * - Packet length is 0
		 * - Packet length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		bool send_packet(RawPacket const& rawPacket, bool checkMtu = false);

		/**
		 * Send a buffer containing packet raw data (including all layers) to the network.
		 * This particular version of the send_packet method should only be used if you already have access to the size
		 * of the network layer of the packet, since it allows you to check the payload size (see packetPayloadLength
		 * parameter) MTU of the live device without incurring a parsing overhead. If the packetPayloadLength is
		 * unknown, please use a different implementation of the send_packet method.
		 * @param[in] packetData The buffer containing the packet raw data
		 * @param[in] packetDataLength The length of the buffer (this is the entire packet, including link layer)
		 * @param[in] packetPayloadLength The length of the payload for the data link layer. This includes all data
		 * apart from the header for the data link layer.
		 * @return True if the packet was sent successfully. False will be returned in the following cases (relevant log
		 * error is printed in any case):
		 * - Device is not opened
		 * - Packet data length is 0
		 * - Packet payload length is larger than device MTU
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		bool send_packet(const uint8_t* packetData, int packetDataLength, int packetPayloadLength);

		/**
		 * Send a buffer containing packet raw data (including all layers) to the network
		 * @param[in] packetData The buffer containing the packet raw data
		 * @param[in] packetDataLength The length of the buffer
		 * @param[in] checkMtu Whether the length of the packet's payload should be checked against the MTU. If enabled
		 * this comes with a small performance penalty. Default value is false to avoid performance overhead. Set to
		 * true if you don't know whether packets fit the live device's MTU and you can afford the overhead.
		 * @param[in] linkType Only used if checkMtu is true. Defines the layer type for parsing the first layer of the
		 * packet. Used for parsing the packet to perform the MTU check. Default value is vanhooks::net::LINKTYPE_ETHERNET.
		 * Ensure this parameter matches the linktype of the packet if checkMtu is true.
		 * @return True if packet was sent successfully. False will be returned in the following cases (relevant log
		 * error is printed in any case):
		 * - Device is not opened
		 * - Packet length is 0
		 * - Packet length is larger than device MTU and checkMtu is true
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		bool send_packet(const uint8_t* packetData, int packetDataLength, bool checkMtu = false,
		                vanhooks::net::LinkLayerType linkType = vanhooks::net::LINKTYPE_ETHERNET);

		/**
		 * Send a parsed Packet to the network
		 * @param[in] packet A pointer to the packet to send. This method treats the packet as read-only, it doesn't
		 * change anything in it
		 * @param[in] checkMtu Whether the length of the packet's payload should be checked against the MTU. Default
		 * value is true, since the packet being passed in has already been parsed, so checking the MTU does not incur
		 * significant processing overhead.
		 * @return True if packet was sent successfully. False will be returned in the following cases (relevant log
		 * error is printed in any case):
		 * - Device is not opened
		 * - Packet length is 0
		 * - Packet length is larger than device MTU and checkMtu is true
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		bool send_packet(Packet* packet, bool checkMtu = true);

		/**
		 * Send an array of RawPacket objects to the network
		 * @param[in] rawPacketsArr The array of RawPacket objects to send. This method treats all packets as read-only,
		 * it doesn't change anything in them
		 * @param[in] arrLength The length of the array
		 * @param[in] checkMtu Whether to check the size of the packet payload against MTU size. Incurs a parsing
		 * overhead. Default value is false to avoid performance overhead. Set to true if you don't know whether packets
		 * fit the live device's MTU and you can afford the overhead.
		 * @return The number of packets sent successfully. Sending a packet can fail if:
		 * - Device is not opened. In this case no packets will be sent, return value will be 0
		 * - Packet length is 0
		 * - Packet length is larger than device MTU and checkMtu is true
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		virtual int send_packets(RawPacket* rawPacketsArr, int arrLength, bool checkMtu = false);

		/**
		 * Send an array of pointers to Packet objects to the network
		 * @param[in] packetsArr The array of pointers to Packet objects to send. This method treats all packets as
		 * read-only, it doesn't change anything in them
		 * @param[in] arrLength The length of the array
		 * @param[in] checkMtu Whether to check the size of the packet payload against MTU size. Default value is true,
		 * since the packets being passed in has already been parsed, so checking the MTU does not incur significant
		 * processing overhead.
		 * @return The number of packets sent successfully. Sending a packet can fail if:
		 * - Device is not opened. In this case no packets will be sent, return value will be 0
		 * - Packet length is 0
		 * - Packet length is larger than device MTU and checkMtu is true
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		virtual int send_packets(Packet** packetsArr, int arrLength, bool checkMtu = true);

		/**
		 * Send a vector of pointers to RawPacket objects to the network
		 * @param[in] rawPackets The array of pointers to RawPacket objects to send. This method treats all packets as
		 * read-only, it doesn't change anything in them
		 * @param[in] checkMtu Whether to check the size of the packet payload against MTU size. Incurs a parsing
		 * overhead. Default value is false to avoid performance overhead. Set to true if you don't know whether packets
		 * fit the live device's MTU and you can afford the overhead.
		 * @return The number of packets sent successfully. Sending a packet can fail if:
		 * - Device is not opened. In this case no packets will be sent, return value will be 0
		 * - Packet length is 0
		 * - Packet length is larger than device MTU and checkMtu is true
		 * - Packet could not be sent due to some error in libpcap/WinPcap/Npcap
		 */
		virtual int send_packets(const RawPacketVector& rawPackets, bool checkMtu = false);

		// implement abstract methods

		/**
		 * Open the device using libpcap pcap_open_live. Opening the device only makes the device ready for use, it
		 * doesn't start packet capturing. For packet capturing the user should call start_capture(). This implies that
		 * calling this method is a must before calling start_capture() (otherwise start_capture() will fail with a
		 * "device not open" error). The device is opened in promiscuous mode
		 * @return True if the device was opened successfully, false otherwise. When opening the device fails an error
		 * will be printed to log as well
		 */
		bool open() override;

		/**
		 * Enables to open a device in a non-default configuration. Configuration has parameters like packet buffer
		 * timeout & size, open in promiscuous/non-promiscuous mode, etc. Please check DeviceConfiguration for more
		 * details
		 * @param[in] config The requested configuration
		 * @return Same as open()
		 */
		bool open(const DeviceConfiguration& config);

		void close() override;

		/**
		 * Clones the current device class
		 * @return Pointer to the copied class
		 */
		PcapLiveDevice* clone() const;

		void get_statistics(IPcapDevice::PcapStats& stats) const override;

	protected:
		pcap_t* do_open(const DeviceConfiguration& config);

		virtual PcapLiveDevice* clone_internal(pcap_if_t& devInterface) const;
	};

}  // namespace vanhooks::net
// ---- end PcapLiveDevice.h ----

// ---- begin PcapLiveDeviceList.h ----
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
	 * @class PcapLiveDeviceList
	 * A singleton class that creates, stores and provides access to all PcapLiveDevice (on Linux) or WinPcapLiveDevice
	 * (on Windows) instances. All live devices are initialized on startup and wrap the network interfaces installed on
	 * the machine. This class enables access to them through their IP addresses or get a vector of all of them so the
	 * user can search them in some other way
	 */
	class PcapLiveDeviceList
	{
	private:
		std::vector<std::unique_ptr<PcapLiveDevice>> live_device_list_;
		// Vector of raw device pointers to keep the signature of get_pcap_live_devices_list, as it returns a reference.
		std::vector<PcapLiveDevice*> live_device_list_view_;

		std::vector<IPv4Address> dns_servers_;

		// private c'tor
		PcapLiveDeviceList();

		static std::vector<std::unique_ptr<PcapLiveDevice>> fetch_all_local_devices();
		static std::vector<IPv4Address> fetch_dns_servers();

	public:
		PcapLiveDeviceList(const PcapLiveDeviceList&) = delete;
		PcapLiveDeviceList(PcapLiveDeviceList&&) noexcept = delete;
		PcapLiveDeviceList& operator=(const PcapLiveDeviceList&) = delete;
		PcapLiveDeviceList& operator=(PcapLiveDeviceList&&) noexcept = delete;

		/**
		 * The access method to the singleton
		 * @return The singleton instance of this class
		 */
		static PcapLiveDeviceList& get_instance()
		{
			static PcapLiveDeviceList instance;
			return instance;
		}

		VH_DEPRECATED("use get_instance()")
		static PcapLiveDeviceList& getInstance() { return get_instance(); }

		/**
		 * @return A vector containing pointers to all live devices currently installed on the machine
		 */
		const std::vector<PcapLiveDevice*>& get_pcap_live_devices_list() const
		{
			return live_device_list_view_;
		};

		VH_DEPRECATED("use get_pcap_live_devices_list()")
		const std::vector<PcapLiveDevice*>& getPcapLiveDevicesList() const { return get_pcap_live_devices_list(); }

		/**
		 * Get a pointer to the live device by its IP address. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddr The IP address defined for the device
		 * @return A pointer to the live device if this IP address exists. nullptr otherwise
		 */
		PcapLiveDevice* get_pcap_live_device_by_ip(const IPAddress& ipAddr) const;

		VH_DEPRECATED("use get_pcap_live_device_by_ip()")
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPAddress& ipAddr) const { return get_pcap_live_device_by_ip(ipAddr); }

		/**
		 * Get a pointer to the live device by its IPv4 address
		 * @param[in] ipAddr The IPv4 address defined for the device
		 * @return A pointer to the live device if this IPv4 address exists. nullptr otherwise
		 */
		PcapLiveDevice* get_pcap_live_device_by_ip(const IPv4Address& ipAddr) const;

		VH_DEPRECATED("use get_pcap_live_device_by_ip()")
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const { return get_pcap_live_device_by_ip(ipAddr); }

		/**
		 * Get a pointer to the live device by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address defined for the device
		 * @return A pointer to the live device if this IPv6 address exists. nullptr otherwise
		 */
		PcapLiveDevice* get_pcap_live_device_by_ip(const IPv6Address& ip6Addr) const;

		VH_DEPRECATED("use get_pcap_live_device_by_ip()")
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const { return get_pcap_live_device_by_ip(ip6Addr); }

		/**
		 * Get a pointer to the live device by its IP address represented as string. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddrAsString The IP address defined for the device as string
		 * @return A pointer to the live device if this IP address is valid and exists. nullptr otherwise
		 */
		PcapLiveDevice* get_pcap_live_device_by_ip(const std::string& ipAddrAsString) const;

		VH_DEPRECATED("use get_pcap_live_device_by_ip()")
		PcapLiveDevice* getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const { return get_pcap_live_device_by_ip(ipAddrAsString); }

		/**
		 * Get a pointer to the live device by its name
		 * @param[in] name The name of the interface (e.g eth0)
		 * @return A pointer to the live device if this name exists. nullptr otherwise
		 */
		PcapLiveDevice* get_pcap_live_device_by_name(const std::string& name) const;

		VH_DEPRECATED("use get_pcap_live_device_by_name()")
		PcapLiveDevice* getPcapLiveDeviceByName(const std::string& name) const { return get_pcap_live_device_by_name(name); }

		/**
		 * Get a pointer to the live device by its IP address or name
		 * @param[in] ipOrName An IP address or name of the interface
		 * @return A pointer to the live device if exists, nullptr otherwise
		 */
		PcapLiveDevice* get_pcap_live_device_by_ip_or_name(const std::string& ipOrName) const;

		/**
		 * @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers
		 * were defined or they couldn't be extracted from some reason
		 */
		const std::vector<IPv4Address>& get_dns_servers() const
		{
			return dns_servers_;
		}

		/**
		 * Copies the current live device list
		 * @return A pointer to the cloned device list
		 */
		PcapLiveDeviceList* clone();

		/**
		 * Reset the live device list and DNS server list, meaning clear and refetch them
		 */
		void reset();
	};

}  // namespace vanhooks::net
// ---- end PcapLiveDeviceList.h ----

// ---- begin WinPcapLiveDevice.h ----
#if defined(_WIN32)

/// @file

#	include "PcapLiveDevice.h"

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class WinPcapLiveDevice
	 * A class that wraps a Windows network interface (each of the interfaces listed in ipconfig).
	 * This class is almost similar in its capabilities to PcapLiveDevice (its parent class) with some small changes
	 * that mainly result from differences between libpcap and WinPcap/Npcap. Please see the reference for
	 * PcapLiveDevice for more details
	 */
	class WinPcapLiveDevice : public PcapLiveDevice
	{
		friend class PcapLiveDeviceList;

	protected:
		int min_amount_of_data_to_copy_from_kernel_to_application_;

		// c'tor is not public, there should be only one for every interface (created by PcapLiveDeviceList)
		WinPcapLiveDevice(pcap_if_t* iface, bool calculateMTU, bool calculateMacAddress, bool calculateDefaultGateway);
		// copy c'tor is not public
		WinPcapLiveDevice(const WinPcapLiveDevice& other);
		WinPcapLiveDevice& operator=(const WinPcapLiveDevice& other);

	public:
		virtual LiveDeviceType get_device_type() const
		{
			return WinPcapDevice;
		}

		bool start_capture(OnPacketArrivesCallback on_packet_arrives, void* onPacketArrivesUserCookie,
		                  int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
		                  void* onStatsUpdateUserCookie);
		bool start_capture(int intervalInSecondsToUpdateStats, OnStatsUpdateCallback onStatsUpdate,
		                  void* onStatsUpdateUserCookie);
		bool start_capture(RawPacketVector& capturedPacketsVector)
		{
			return PcapLiveDevice::start_capture(capturedPacketsVector);
		}

		using PcapLiveDevice::send_packets;
		virtual int send_packets(RawPacket* rawPacketsArr, int arrLength);

		/**
		 * WinPcap/Npcap have a feature (that doesn't exist in libpcap) to change the minimum amount of data in the
		 * kernel buffer that causes a read from the application to return (unless the timeout expires). Please see
		 * documentation for pcap_setmintocopy for more info. This method enables the user to change this size. Note the
		 * device must be open for this method to work
		 * @param[in] size The size to set in bytes
		 * @return True if set succeeded, false if the device is closed or if pcap_setmintocopy failed
		 */
		bool set_min_amount_of_data_to_copy_from_kernel_to_application(int size);

		/**
		 * @return The current amount of data in the kernel buffer that causes a read from the application to return
		 * (see also set_min_amount_of_data_to_copy_from_kernel_to_application())
		 */
		int get_min_amount_of_data_to_copy_from_kernel_to_application() const
		{
			return min_amount_of_data_to_copy_from_kernel_to_application_;
		}

	protected:
		WinPcapLiveDevice* clone_internal(pcap_if_t& devInterface) const override;
	};

}  // namespace vanhooks::net

#endif  // _WIN32
// ---- end WinPcapLiveDevice.h ----

// ---- begin PcapRemoteDevice.h ----
#if defined(_WIN32)

#	include <vector>
#	include <memory>
#	include "PcapLiveDevice.h"

/// @file

struct pcap_rmtauth;

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct PcapRemoteAuthentication
	 * The remote daemon (rpcapd) can be configured to require authentication before allowing a client to connect. This
	 * is done for security reasons of course. This struct wraps the WinPcap/Npcap authentication object (pcap_rmtauth)
	 * and can (but not must) be given to PcapRemoteDeviceList when initiating a connection to the remote daemon
	 */
	struct PcapRemoteAuthentication
	{
	public:
		/**
		 * A constructor that sets username and password
		 * @param[in] username The username for authentication with the remote daemon
		 * @param[in] password The password for authentication with the remote daemon
		 */
		PcapRemoteAuthentication(const std::string& username, const std::string& password) : user_name(username)
		{
			this->password = password;
		}

		/**
		 * A copy c'tor for this object
		 * @param[in] other The object to copy from
		 */
		PcapRemoteAuthentication(const PcapRemoteAuthentication& other)
		    : user_name(other.user_name), password(other.password)
		{}

		/**
		 * The username for authentication
		 */
		std::string user_name;

		/**
		 * The password for authentication
		 */
		std::string password;

		/**
		 * A conversion method from PcapRemoteAuthentication to pcap_rmtauth. Note: the char* pointers of the returned
		 * pcap_rmtauth points to the same places in memory as PcapRemoteAuthentication::user_name and
		 * PcapRemoteAuthentication::password so the user should avoid freeing this memory
		 * @return A pcap_rmtauth that is converted from this class
		 */
		pcap_rmtauth get_pcap_rm_auth() const;
	};

	/**
	 * @class PcapRemoteDevice
	 * A class that provides a C++ wrapper for WinPcap/Npcap Remote Capture feature. This feature allows to interact to
	 * a remote machine and capture packets that are being transmitted on the remote network interfaces. This requires a
	 * remote daemon (called rpcapd) which performs the capture and sends data back and the local client (represented by
	 * PcapRemoteDevice) that sends the appropriate commands and receives the captured data. You can read more about
	 * this feature in WinPcap Remote Capture manual: https://www.winpcap.org/docs/docs_412/html/group__remote.html<BR>
	 * Since this feature is supported in WinPcap and Npcap only and not in libpcap, PcapRemoteDevice can only be used
	 * in Windows only.<BR> This class provides a wrapper for the local client, meaning it assumes the daemon (rpcapd)
	 * is already running on the remote machine and it tries to connect to it and start receiving/sending packets
	 * from/to it. This class assumes rpcapd is in passive mode, meaning PcapRemoteDevice connects to the remote daemon,
	 * sends the appropriate commands to it, and starts capturing packets, rather than letting the daemon connect to the
	 * client by itself. Using PcapRemoteDevice is very similar to using the other live devices (PcapLiveDevice or
	 * WinPcapLiveDevice), meaning the API's are the same and the same logic is used (for example: capturing is done on
	 * a different thread, sending packets are done on the same thread, etc.). For the full API and explanations, please
	 * refer to PcapLiveDevice. The reason for the similar API is that WinPcap/Npcap's API is very similar between
	 * Remote Capture and local network interface capture. The things that are different are some are some
	 * implementation details, mainly in making the connection to the remote daemon, and the way the user can get the
	 * instance of PcapRemoteDevice. For more details on that please refer to PcapRemoteDeviceList
	 */
	class PcapRemoteDevice : public PcapLiveDevice
	{
		friend class PcapRemoteDeviceList;

	private:
		IPAddress remote_machine_ip_address_;
		uint16_t remote_machine_port_;
		std::shared_ptr<PcapRemoteAuthentication> remote_authentication_;

		// c'tor is private, as only PcapRemoteDeviceList should create instances of it, and it'll create only one for
		// every remote interface
		PcapRemoteDevice(pcap_if_t* iface, std::shared_ptr<PcapRemoteAuthentication> remoteAuthentication,
		                 const IPAddress& remoteMachineIP, uint16_t remoteMachinePort);

	public:
		PcapRemoteDevice(const PcapRemoteDevice&) = delete;
		PcapRemoteDevice(PcapRemoteDevice&&) noexcept = delete;
		PcapRemoteDevice& operator=(const PcapRemoteDevice&) = delete;
		PcapRemoteDevice& operator=(PcapRemoteDevice&&) noexcept = delete;

		~PcapRemoteDevice() override
		{}

		/**
		 * @return The IP address of the remote machine where packets are transmitted from the remote machine to the
		 * client machine
		 */
		IPAddress get_remote_machine_ip_address() const
		{
			return remote_machine_ip_address_;
		}

		/**
		 * @return The port of the remote machine where packets are transmitted from the remote machine to the client
		 * machine
		 */
		uint16_t get_remote_machine_port() const
		{
			return remote_machine_port_;
		}

		/**
		 * @return The type of the device (libPcap, WinPcap/Npcap or a remote device)
		 */
		LiveDeviceType get_device_type() const override
		{
			return RemoteDevice;
		}

		/**
		 * MTU isn't supported for remote devices
		 * @return 0
		 */
		uint32_t get_mtu() const override;

		/**
		 * MAC address isn't supported for remote devices
		 * @return MacAddress#Zero
		 */
		MacAddress get_mac_address() const override;

		/**
		 * Open the device using pcap_open. Opening the device makes the connection to the remote daemon (including
		 * authentication if needed and provided). If this methods succeeds it means the connection to the remote daemon
		 * succeeded and the device is ready for use. As in PcapLiveDevice, packet capturing won't start yet. For packet
		 * capturing the user should call start_capture(). This implies that calling this method is a must before calling
		 * start_capture() (otherwise start_capture() will fail with a "device not open" error). The remote daemon is
		 * asked to capture packets in promiscuous mode
		 * @return True if the device was opened successfully, false otherwise. When opening the device fails an error
		 * will be printed to log as well, including the WinPcap/Npcap error if exists
		 */
		bool open() override;

		void get_statistics(IPcapDevice::PcapStats& stats) const override;
	};

}  // namespace vanhooks::net

#endif  // _WIN32
// ---- end PcapRemoteDevice.h ----

// ---- begin PcapRemoteDeviceList.h ----
#if defined(_WIN32)

#	include <memory>
#	include "IpAddress.h"
#	include "PcapRemoteDevice.h"
#	include "DeprecationUtils.h"

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class PcapRemoteDeviceList
	 * A class that creates, stores and provides access to all instances of PcapRemoteDevice for a certain remote
	 * machine. To get an instance of this class use one of the static methods of get_remote_device_list(). These methods
	 * creates a PcapRemoteDeviceList instance for the certain remote machine which holds a list of PcapRemoteDevice
	 * instances, one for each remote network interface. Note there is not a public constructor for this class, so the
	 * only way to get an instance of it is through get_remote_device_list(). After getting this object, this class
	 * provides ways to access the PcapRemoteDevice instances: either through IP address of the remote network interface
	 * or by iterating the PcapRemoteDevice instances (through the PcapRemoteDeviceList#RemoteDeviceListIterator
	 * iterator)<BR> Since Remote Capture is supported in WinPcap and Npcap only, this class is available in Windows
	 * only
	 */
	class PcapRemoteDeviceList
	{
	private:
		std::vector<PcapRemoteDevice*> remote_device_list_;
		IPAddress remote_machine_ip_address_;
		uint16_t remote_machine_port_;
		std::shared_ptr<PcapRemoteAuthentication> remote_authentication_;

		// private c'tor. User should create the list via static methods PcapRemoteDeviceList::create_remote_device_list()
		PcapRemoteDeviceList(const IPAddress& ipAddress, uint16_t port,
		                     std::shared_ptr<PcapRemoteAuthentication> remoteAuth,
		                     std::vector<PcapRemoteDevice*> deviceList);

	public:
		/**
		 * Iterator object that can be used for iterating all PcapRemoteDevice in list
		 */
		using RemoteDeviceListIterator = typename std::vector<PcapRemoteDevice*>::iterator;

		/**
		 * Const iterator object that can be used for iterating all PcapRemoteDevice in a constant list
		 */
		using ConstRemoteDeviceListIterator = typename std::vector<PcapRemoteDevice*>::const_iterator;

		PcapRemoteDeviceList(const PcapRemoteDeviceList&) = delete;
		PcapRemoteDeviceList(PcapRemoteDeviceList&&) noexcept = delete;
		PcapRemoteDeviceList& operator=(const PcapRemoteDeviceList&) = delete;
		PcapRemoteDeviceList& operator=(PcapRemoteDeviceList&&) noexcept = delete;

		~PcapRemoteDeviceList();

		/**
		 * A static method for creating a PcapRemoteDeviceList instance for a certain remote machine. This methods
		 * creates the instance, and also creates a list of PcapRemoteDevice instances stored in it, one for each remote
		 * network interface. Notice this method allocates the PcapRemoteDeviceList instance and returns a pointer to
		 * it. It's the user responsibility to free it when done using it<BR> This method overload is for remote daemons
		 * which don't require authentication for accessing them. For daemons which do require authentication use the
		 * other method overload
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		 * daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @return A pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be
		 * printed to log in each case):
		 * - IP address provided is nullptr or not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		 *   devices on the remote machine
		 * @deprecated This factory function has been deprecated in favor of 'create_remote_device_list' factory for better
		 * memory safety.
		 */
		VH_DEPRECATED("Please use 'create_remote_device_list' factory method instead.")
		static PcapRemoteDeviceList* get_remote_device_list(const IPAddress& ipAddress, uint16_t port);

		/**
		 * A static method for creating a PcapRemoteDeviceList instance for a specific remote machine.
		 * This methods creates the instance and populates it with PcapRemoteDevice instances.
		 * Each PcapRemoteDevice instance corresponds to a network interface on the remote machine.
		 *
		 * This method overload is for remote daemons which don't require authentication for accessing them.
		 * For daemons which do require authentication use the other method overload.
		 *
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		 * daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @return A smart pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will
		 * be printed to log in each case):
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		 *   devices on the remote machine
		 */
		static std::unique_ptr<PcapRemoteDeviceList> create_remote_device_list(const IPAddress& ipAddress, uint16_t port);

		/**
		 * An overload of the previous get_remote_device_list() method but with authentication support. This method is
		 * suitable for connecting to remote daemons which require authentication for accessing them
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		 * daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth A pointer to the authentication object which contains the username and password for
		 * connecting to the remote daemon
		 * @return A pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be
		 * printed to log in each case):
		 * - IP address provided is nullptr or not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		 *   devices on the remote machine
		 * @deprecated This factory function has been deprecated in favor of 'create_remote_device_list' factory for better
		 * memory safety.
		 */
		VH_DEPRECATED("Please use 'create_remote_device_list' factory method instead.")
		static PcapRemoteDeviceList* get_remote_device_list(const IPAddress& ipAddress, uint16_t port,
		                                                 PcapRemoteAuthentication* remoteAuth);

		/**
		 * A static method for creating a PcapRemoteDeviceList instance for a specific remote machine.
		 * This methods creates the instance and populates it with PcapRemoteDevice instances.
		 * Each PcapRemoteDevice instance corresponds to a network interface on the remote machine.
		 *
		 * This method overload is for remote daemons which require authentication for accessing them.
		 * If no authentication is required, use the other method overload.
		 *
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		 * daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth A pointer to the authentication object which contains the username and password for
		 * connecting to the remote daemon
		 * @return A smart pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will
		 * be printed to log in each case):
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		 *   devices on the remote machine
		 */
		static std::unique_ptr<PcapRemoteDeviceList> create_remote_device_list(const IPAddress& ipAddress, uint16_t port,
		                                                                    PcapRemoteAuthentication const* remoteAuth);

		/**
		 * @return The IP address of the remote machine
		 */
		IPAddress get_remote_machine_ip_address() const
		{
			return remote_machine_ip_address_;
		}

		/**
		 * @return The port of the remote machine where packets are transmitted from the remote machine to the client
		 * machine
		 */
		uint16_t get_remote_machine_port() const
		{
			return remote_machine_port_;
		}

		/**
		 * Search a PcapRemoteDevice in the list by its IPv4 address
		 * @param[in] ip4Addr The IPv4 address
		 * @return The PcapRemoteDevice if found, nullptr otherwise
		 */
		PcapRemoteDevice* get_remote_device_by_ip(const IPv4Address& ip4Addr) const;

		/**
		 * Search a PcapRemoteDevice in the list by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address
		 * @return The PcapRemoteDevice if found, nullptr otherwise
		 */
		PcapRemoteDevice* get_remote_device_by_ip(const IPv6Address& ip6Addr) const;

		/**
		 * Search a PcapRemoteDevice in the list by its IP address (IPv4 or IPv6)
		 * @param[in] ipAddr The IP address
		 * @return The PcapRemoteDevice if found, nullptr otherwise
		 */
		PcapRemoteDevice* get_remote_device_by_ip(const IPAddress& ipAddr) const;

		/**
		 * Search a PcapRemoteDevice in the list by its IP address
		 * @param[in] ipAddrAsString The IP address in string format
		 * @return The PcapRemoteDevice if found, nullptr otherwise
		 */
		PcapRemoteDevice* get_remote_device_by_ip(const std::string& ipAddrAsString) const;

		/**
		 * @return An iterator object pointing to the first PcapRemoteDevice in list
		 */
		RemoteDeviceListIterator begin()
		{
			return remote_device_list_.begin();
		}

		/**
		 * @return A const iterator object pointing to the first PcapRemoteDevice in list
		 */
		ConstRemoteDeviceListIterator begin() const
		{
			return remote_device_list_.begin();
		}

		/**
		 * @return An iterator object pointing to the last PcapRemoteDevice in list
		 */
		RemoteDeviceListIterator end()
		{
			return remote_device_list_.end();
		}

		/**
		 * @return A const iterator object pointing to the last PcapRemoteDevice in list
		 */
		ConstRemoteDeviceListIterator end() const
		{
			return remote_device_list_.end();
		}
	};

}  // namespace vanhooks::net

#endif  // _WIN32
// ---- end PcapRemoteDeviceList.h ----

// ---- begin PcapUtils.h ----
// Forward declarations
struct pcap;
typedef pcap pcap_t;
struct pcap_if;
typedef pcap_if pcap_if_t;

namespace vanhooks::net
{
	/// @cond VH_INTERNAL

	namespace internal
	{
		/**
		 * @class PcapCloseDeleter
		 * A deleter that cleans up a pcap_t structure by calling pcap_close.
		 */
		struct PcapCloseDeleter
		{
			void operator()(pcap_t* ptr) const;
		};

		/**
		 * @class PcapFreeAllDevsDeleter
		 * A deleter that frees an interface list of pcap_if_t ptr by calling 'pcap_freealldevs' function on it.
		 */
		struct PcapFreeAllDevsDeleter
		{
			void operator()(pcap_if_t* ptr) const;
		};
	}  // namespace internal

	/// @endcond
}  // namespace vanhooks::net
// ---- end PcapUtils.h ----

// ---- begin DeviceUtils.h ----
/// @file

#include <memory>

namespace vanhooks::net
{
	/// @cond VH_INTERNAL

	namespace internal
	{
		/**
		 * Fetches a list of all network devices on the local machine that LibPcap/WinPcap/NPcap can find.
		 * @return A smart pointer to an interface list structure.
		 * @throws std::runtime_error The system encountered an error fetching the devices.
		 */
		std::unique_ptr<pcap_if_t, PcapFreeAllDevsDeleter> get_all_local_pcap_devices();
	}  // namespace internal

	/// @endcond
}  // namespace vanhooks::net
// ---- end DeviceUtils.h ----

// ---- begin RawSocketDevice.h ----
/// @file


/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @class RawSocketDevice
	 * A class that wraps the raw socket functionality. A raw socket is a network socket that allows direct sending and
	 * receiving of IP packets without any protocol-specific transport layer formatting (taken from Wikipedia:
	 * https://en.wikipedia.org/wiki/Network_socket#Raw_socket). This wrapper class enables creation of a raw socket,
	 * binding it to a network interface, and then receiving and sending packets on it. Current implementation supports
	 * only Windows and Linux because other platforms provide poor support for raw sockets making them practically
	 * unusable. There are also major differences between Linux and Windows in raw socket implementation, let's mention
	 * some of the:
	 *  - On Windows administrative privileges are required for raw sockets creation, meaning the process running the
	 *    code has to have these privileges. In Linux 'sudo' is required
	 *  - On Windows raw sockets are implemented in L3, meaning the L2 (Ethernet) layer is omitted by the socket and
	 *    only L3 and up are visible to the user. On Linux raw sockets are implemented on L2, meaning all layers
	 *    (including the Ethernet data) are visible to the user.
	 *  - On Windows sending packets is not supported, a raw socket can only receive packets. On Linux both send and
	 *    receive are supported
	 *  - Linux doesn't require binding to a specific network interface for receiving packets, but it does require
	 *    binding for sending packets. Windows requires binding for receiving packets. For the sake of keeping a unified
	 *    and simple cross-platform interface this class requires binding for both Linux and Windows, on both send and
	 *    receive
	 *
	 * More details about opening the raw socket, receiving and sending packets are explained in the corresponding class
	 * methods. Raw sockets are supported for both IPv4 and IPv6, so you can create and bind raw sockets to each of the
	 * two. Also, there is no limit on the number of sockets opened for a specific IP address or network interface, so
	 * you can create multiple instances of this class and bind all of them to the same interface and IP address.
	 */
	class RawSocketDevice : public IDevice
	{
	public:
		/**
		 * An enum for reporting packet receive results
		 */
		enum RecvPacketResult
		{
			/** Receive success */
			RecvSuccess = 0,
			/** Receive timeout - timeout expired without any packets being captured */
			RecvTimeout = 1,
			/** Receive would block - in non-blocking mode if there are no packets in the rx queue the receive method
			 * will return immediately with this return value */
			RecvWouldBlock = 2,
			/** Receive error, usually will be followed by an error log */
			RecvError = 3
		};

		/*
		 * A c'tor for this class. This c'tor doesn't create the raw socket, but rather initializes internal structures.
		 * The actual raw socket creation is done in the open() method. Each raw socket is bound to a network interface
		 * which means packets will be received and sent from only from this network interface only
		 * @param[in] interfaceIP The network interface IP to bind the raw socket to. It can be either an IPv4 or IPv6
		 * address (both are supported in raw sockets)
		 */
		explicit RawSocketDevice(const IPAddress& interfaceIP);

		/**
		 * A d'tor for this class. It closes the raw socket if not previously closed by calling close()
		 */
		~RawSocketDevice();

		/**
		 * Receive a packet on the raw socket. This method has several modes of operation:
		 *  - Blocking/non-blocking - in blocking mode the method will not return until a packet is received on the
		 *    socket or until the timeout expires. In non-blocking mode it will return immediately and in case no
		 *    packets are on the receive queue RawSocketDevice#RecvWouldBlock will be returned. Unless specified
		 *    otherwise, the default value is blocking mode
		 *  - Receive timeout - in blocking mode, the user can set a timeout to wait until a packet is received. If the
		 *    timeout expires and no packets were received, the method will return RawSocketDevice#RecvTimeout. The
		 *    default value is a negative value which means no timeout
		 *
		 * There is a slight difference on this method's behavior between Windows and Linux around how packets are
		 * received. On Linux the received packet contains all layers starting from the L2 (Ethernet). However on
		 * Windows raw socket are integrated in L3 level so the received packet contains only L3 (IP) layer and up.
		 * @param[out] rawPacket An empty packet instance where the received packet data will be written to
		 * @param[in] blocking Indicates whether to run in blocking or non-blocking mode. Default value is blocking
		 * @param[in] timeout When in blocking mode, specifies the timeout [in seconds] to wait for a packet. If timeout
		 * expired and no packets were captured the method will return RawSocketDevice#RecvTimeout. Zero or negative
		 * values mean no timeout. The default value is no timeout. The timeout precision is in milliseconds, for
		 * example a timeout of 0.123 means 123 milliseconds.
		 * @return The method returns one on the following values:
		 *  - RawSocketDevice#RecvSuccess is returned if a packet was received successfully
		 *  - RawSocketDevice#RecvTimeout is returned if in blocking mode and timeout expired
		 *  - RawSocketDevice#RecvWouldBlock is returned if in non-blocking mode and no packets were captured
		 *  - RawSocketDevice#RecvError is returned if an error occurred such as device is not opened or the recv
		 *    operation returned some error. A log message will be followed specifying the error and error code
		 */
		RecvPacketResult receive_packet(RawPacket& rawPacket, bool blocking = true, double timeout = -1);

		/**
		 * Receive packets into a packet vector for a certain amount of time. This method starts a timer and invokes the
		 * receive_packet() method in blocking mode repeatedly until the timeout expires. All packets received
		 * successfully are put into a packet vector
		 * @param[out] packetVec The packet vector to add the received packet to
		 * @param[in] timeout Timeout in seconds to receive packets on the raw socket. The timeout precision is in
		 * milliseconds, for example a timeout of 0.123 means 123 milliseconds.
		 * @param[out] failedRecv Number of receive attempts that failed
		 * @return The number of packets received successfully
		 */
		int receive_packets(RawPacketVector& packetVec, double timeout, int& failedRecv);

		/**
		 * Send an Ethernet packet to the network. L2 protocols other than Ethernet are not supported in raw sockets.
		 * The entire packet is sent as is, including the original Ethernet and IP data.
		 * This method is only supported in Linux as Windows doesn't allow sending packets from raw sockets. Using
		 * it from other platforms will also return "false" with a corresponding error log message
		 * @param[in] rawPacket The packet to send
		 * @return True if packet was sent successfully or false if the socket is not open, if the packet is not
		 * Ethernet or if there was a failure sending the packet
		 */
		bool send_packet(const RawPacket* rawPacket);

		/**
		 * Send a set of Ethernet packets to the network. L2 protocols other than Ethernet are not supported by raw
		 * sockets. The entire packet is sent as is, including the original Ethernet and IP data. This method is only
		 * supported in Linux as Windows doesn't allow sending packets from raw sockets. Using it from other platforms
		 * will return "false" with an appropriate error log message
		 * @param[in] packetVec The set of packets to send
		 * @return The number of packets sent successfully. For packets that weren't sent successfully there will be a
		 * corresponding error message printed to log
		 */
		int send_packets(const RawPacketVector& packetVec);

		// overridden methods

		/**
		 * Open the device by creating a raw socket and binding it to the network interface specified in the c'tor
		 * @return True if device was opened successfully, false otherwise with a corresponding error log message
		 */
		bool open() override;

		/**
		 * Close the raw socket
		 */
		void close() override;

	private:
		enum SocketFamily
		{
			Ethernet = 0,
			IPv4 = 1,
			IPv6 = 2
		};

		SocketFamily sock_family_;
		void* socket_;
		IPAddress interface_ip_;

		RecvPacketResult get_error(int& errorCode) const;
	};
}  // namespace vanhooks::net
// ---- end RawSocketDevice.h ----

// ---- begin NetworkUtils.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class NetworkUtils
	 * This class bundles several network utilities that are very common and useful. These utilities use VanHooks and
	 * Packet++ packet crafting and processing capabilities. This class is a singleton and can be access by
	 * get_instance() only
	 */
	class NetworkUtils
	{
	public:
		/**
		 * The access method to the singleton
		 * @return The singleton instance of this class
		 */
		static NetworkUtils& get_instance()
		{
			static NetworkUtils instance;
			return instance;
		}

		/**
		 * Default timeout used for several utilities. Currently set to 5 seconds
		 */
		static const int DefaultTimeout;

		/**
		 * Resolve the MAC address for a given IPv4 address. It's done using the ARP protocol: send an ARP request and
		 * interpret the response
		 * @param[in] ipAddr The IPv4 address to resolve MAC address to
		 * @param[in] device The interface to send and receive the ARP packets on
		 * @param[out] arpResponseTimeMS An output parameter that will contain the time in milliseconds that took the
		 * ARP response to arrive
		 * @param[in] sourceMac An optional parameter to set the source MAC address that will be sent with the ARP
		 * request if this parameter isn't set or set with MacAddress#Zero the MAC address of the interface will be used
		 * @param[in] sourceIP An optional parameter to set the source IPv4 address that will be sent with the ARP
		 * request if this parameter isn't set or set with IPv4Address#Zero the default IPv4 address of the interface
		 * will be used
		 * @param[in] arpTimeout An optional parameter to set the timeout to wait for the ARP response to return.
		 * If this parameter isn't set or set with a number smaller than 0, a default timeout of 5 seconds will be set
		 * @return The resolved MAC address or MacAddress#Zero if an error occurred or address could not be resolved.
		 * Errors will be printed to log
		 */
		MacAddress get_mac_address(IPv4Address ipAddr, PcapLiveDevice* device, double& arpResponseTimeMS,
		                         MacAddress sourceMac = MacAddress::Zero, IPv4Address sourceIP = IPv4Address::Zero,
		                         int arpTimeout = -1) const;

		/**
		 * Resolve an IPv4 address for a given hostname. Resolving is done in multiple phases: first resolving the LAN
		 * gateway MAC address (or default gateway if a gateway isn't provided) using ARP protocol (by using
		 * NetworkUtils#get_mac_address() ). Then a DNS request is sent to a DNS server (if specified) or to the LAN
		 * gateway (if DNS server is not specified). The DNS response is decoded and the IPv4 address is determined. In
		 * addition the method outputs the time it took the DNS response to arrive and the DNS TTL written on the DNS
		 * response. If DNS response doesn't contain an IPv4 address resolving an IPv4Address#Zero will be returned.
		 * @param[in] hostname The hostname to resolve
		 * @param[in] device The interface to send and receive packets on
		 * @param[out] dnsResponseTimeMS When method returns successfully will contain the time it took to receive the
		 * DNS response (in milli-seconds)
		 * @param[out] dnsTTL When method returns successfully will contain The DNS TTL written in the DNS response
		 * @param[in] dnsTimeout An optional parameter to specify the timeout to wait for a DNS response. If not
		 * specified the default timeout is 5 sec
		 * @param[in] dnsServerIP An optional parameter to specify the DNS server IP to send the DNS request to. If not
		 * specified or specified with IPv4Address#Zero the DNS request will be sent to the default DNS server
		 * configured in the system
		 * @param[in] gatewayIP An optional parameter to specify the LAN gateway to send the DNS request through. If not
		 * specified or specified with IPv4Address#Zero the interface's default gateway will be used
		 * @return The resolved IPv4 address or IPv4Address#Zero if something went wrong (in this case an error will be
		 * printed to log)
		 */
		IPv4Address get_ipv4_address(const std::string& hostname, PcapLiveDevice* device, double& dnsResponseTimeMS,
		                           uint32_t& dnsTTL, int dnsTimeout = -1, IPv4Address dnsServerIP = IPv4Address::Zero,
		                           IPv4Address gatewayIP = IPv4Address::Zero) const;

	private:
		// private c'tor
		NetworkUtils()
		{}
	};

}  // namespace vanhooks::net
// ---- end NetworkUtils.h ----

