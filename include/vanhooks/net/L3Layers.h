#pragma once

// ===== Consolidated header: L3Layers.h =====
// Merges: IPv4Layer, IPv6Extensions, IPv6Layer, IcmpLayer, IcmpV6Layer, IgmpLayer, GreLayer, IPSecLayer, VxlanLayer, VrrpLayer, GtpLayer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "PacketCore.h"
#include "Common.h"

// ---- begin IPv4Layer.h ----
#include <string.h>
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct iphdr
	 * Represents an IPv4 protocol header
	 */
#pragma pack(push, 1)
	struct iphdr
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** IP header length, has the value of 5 for IPv4 */
		uint8_t internetHeaderLength : 4,
		    /** IP version number, has the value of 4 for IPv4 */
		    ipVersion : 4;
#else
		/** IP version number, has the value of 4 for IPv4 */
		uint8_t ipVersion : 4,
		    /** IP header length, has the value of 5 for IPv4 */
		    internetHeaderLength : 4;
#endif
		/** type of service, same as Differentiated Services Code Point (DSCP)*/
		uint8_t typeOfService;
		/** Entire packet (fragment) size, including header and data, in bytes */
		uint16_t totalLength;
		/** Identification field. Primarily used for uniquely identifying the group of fragments of a single IP
		 * datagram*/
		uint16_t ipId;
		/** Fragment offset field, measured in units of eight-byte blocks (64 bits) */
		uint16_t fragmentOffset;
		/** An eight-bit time to live field helps prevent datagrams from persisting (e.g. going in circles) on an
		 * internet.  In practice, the field has become a hop count */
		uint8_t timeToLive;
		/** Defines the protocol used in the data portion of the IP datagram. Must be one of ::IPProtocolTypes */
		uint8_t protocol;
		/** Error-checking of the header */
		uint16_t headerChecksum;
		/** IPv4 address of the sender of the packet */
		uint32_t ipSrc;
		/** IPv4 address of the receiver of the packet */
		uint32_t ipDst;
		/*The options start here. */
	};
#pragma pack(pop)

	/**
	 * An enum for all possible IPv4 and IPv6 protocol types
	 */
	enum IPProtocolTypes
	{
		/** Dummy protocol for TCP */
		PACKETPP_IPPROTO_IP = 0,
		/** IPv6 Hop-by-Hop options */
		PACKETPP_IPPROTO_HOPOPTS = 0,
		/** Internet Control Message Protocol */
		PACKETPP_IPPROTO_ICMP = 1,
		/** Internet Gateway Management Protocol */
		PACKETPP_IPPROTO_IGMP = 2,
		/** IPIP tunnels (older KA9Q tunnels use 94) */
		PACKETPP_IPPROTO_IPIP = 4,
		/** Transmission Control Protocol */
		PACKETPP_IPPROTO_TCP = 6,
		/** Exterior Gateway Protocol */
		PACKETPP_IPPROTO_EGP = 8,
		/** PUP protocol */
		PACKETPP_IPPROTO_PUP = 12,
		/** User Datagram Protocol */
		PACKETPP_IPPROTO_UDP = 17,
		/** XNS IDP protocol */
		PACKETPP_IPPROTO_IDP = 22,
		/** IPv6 header */
		PACKETPP_IPPROTO_IPV6 = 41,
		/** IPv6 Routing header */
		PACKETPP_IPPROTO_ROUTING = 43,
		/** IPv6 fragmentation header */
		PACKETPP_IPPROTO_FRAGMENT = 44,
		/** GRE protocol */
		PACKETPP_IPPROTO_GRE = 47,
		/** encapsulating security payload */
		PACKETPP_IPPROTO_ESP = 50,
		/** authentication header */
		PACKETPP_IPPROTO_AH = 51,
		/** ICMPv6 */
		PACKETPP_IPPROTO_ICMPV6 = 58,
		/** IPv6 no next header */
		PACKETPP_IPPROTO_NONE = 59,
		/** IPv6 Destination options */
		PACKETPP_IPPROTO_DSTOPTS = 60,
		/** VRRP protocol */
		PACKETPP_IPPROTO_VRRP = 112,
		/** Raw IP packets */
		PACKETPP_IPPROTO_RAW = 255,
		/** Maximum value */
		PACKETPP_IPPROTO_MAX
	};

	/**
	 * An enum for supported IPv4 option types
	 */
	enum IPv4OptionTypes
	{
		/** End of Options List */
		IPV4OPT_EndOfOptionsList = 0,
		/** No Operation */
		IPV4OPT_NOP = 1,
		/** Record Route */
		IPV4OPT_RecordRoute = 7,
		/** MTU Probe */
		IPV4OPT_MTUProbe = 11,
		/** MTU Reply */
		IPV4OPT_MTUReply = 12,
		/** Quick-Start */
		IPV4OPT_QuickStart = 25,
		/** Timestamp */
		IPV4OPT_Timestamp = 68,
		/** Traceroute */
		IPV4OPT_Traceroute = 82,
		/** Security */
		IPV4OPT_Security = 130,
		/** Loose Source Route */
		IPV4OPT_LooseSourceRoute = 131,
		/** Extended Security */
		IPV4OPT_ExtendedSecurity = 133,
		/** Commercial Security */
		IPV4OPT_CommercialSecurity = 134,
		/** Stream ID */
		IPV4OPT_StreamID = 136,
		/** Strict Source Route */
		IPV4OPT_StrictSourceRoute = 137,
		/** Extended Internet Protocol */
		IPV4OPT_ExtendedInternetProtocol = 145,
		/** Address Extension */
		IPV4OPT_AddressExtension = 147,
		/** Router Alert */
		IPV4OPT_RouterAlert = 148,
		/** Selective Directed Broadcast */
		IPV4OPT_SelectiveDirectedBroadcast = 149,
		/** Dynamic Packet State */
		IPV4OPT_DynamicPacketState = 151,
		/** Upstream Multicast Pkt. */
		IPV4OPT_UpstreamMulticastPkt = 152,
		/** Unknown IPv4 option */
		IPV4OPT_Unknown
	};

#define VH_IP_DONT_FRAGMENT 0x40
#define VH_IP_MORE_FRAGMENTS 0x20

	/**
	 * @struct IPv4TimestampOptionValue
	 * A struct representing a parsed value of the IPv4 timestamp option. This struct is used returned in
	 * IPv4OptionData#getTimestampOptionValue() method
	 */
	struct IPv4TimestampOptionValue
	{
		/**
		 * An enum for IPv4 timestamp option types
		 */
		enum TimestampType
		{
			/** Value containing only timestamps */
			TimestampOnly = 0,
			/** Value containing both timestamps and IPv4 addresses */
			TimestampAndIP = 1,
			/** The IPv4 addresses are prespecified */
			TimestampsForPrespecifiedIPs = 2,
			/** Invalid or unknown value type */
			Unknown = 3
		};

		/** The timestamp value type */
		TimestampType type;

		/** A list of timestamps parsed from the IPv4 timestamp option value */
		std::vector<uint32_t> timestamps;

		/** A list of IPv4 addresses parsed from the IPv4 timestamp option value */
		std::vector<IPv4Address> ipAddresses;

		/** The default constructor */
		IPv4TimestampOptionValue() : type(IPv4TimestampOptionValue::Unknown)
		{}

		/**
		 * Clear the structure. Clean the timestamps and IP addresses vectors and set the type as
		 * IPv4TimestampOptionValue#Unknown
		 */
		void clear()
		{
			type = IPv4TimestampOptionValue::Unknown;
			timestamps.clear();
			ipAddresses.clear();
		}
	};

	/**
	 * @class IPv4Option
	 * A wrapper class for IPv4 options. This class does not create or modify IPv4 option records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class IPv4Option : public TLVRecord<uint8_t, uint8_t>
	{
	public:
		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the IPv4 option raw data
		 */
		explicit IPv4Option(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		~IPv4Option()
		{}

		/**
		 * A method for parsing the IPv4 option value as a list of IPv4 addresses. This method is relevant only for
		 * certain types of IPv4 options which their value is a list of IPv4 addresses such as ::IPV4OPT_RecordRoute,
		 * ::IPV4OPT_StrictSourceRoute, ::IPV4OPT_LooseSourceRoute, etc. This method returns a vector of the IPv4
		 * addresses. Blank IP addresses (meaning zeroed addresses - 0.0.0.0) will not be added to the returned list. If
		 * some error occurs during the parsing or the value is invalid an empty vector is returned
		 * @return A vector of IPv4 addresses parsed from the IPv4 option value
		 */
		std::vector<IPv4Address> getValueAsIpList() const
		{
			std::vector<IPv4Address> res;

			if (m_Data == nullptr)
				return res;

			size_t dataSize = getDataSize();
			if (dataSize < 2)
				return res;

			uint8_t valueOffset = static_cast<uint8_t>(1);

			while (static_cast<size_t>(valueOffset) < dataSize)
			{
				uint32_t curValue;
				memcpy(&curValue, m_Data->recordValue + valueOffset, sizeof(uint32_t));
				if (curValue == 0)
					break;

				res.push_back(IPv4Address(curValue));

				valueOffset += static_cast<uint8_t>(4);
			}

			return res;
		}

		/**
		 * A method for parsing the IPv4 timestamp option value. This method is relevant only for IPv4 timestamp option.
		 * For other option types an empty result will be returned. The returned structure contains the timestamp value
		 * type (timestamp only, timestamp + IP addresses, etc.) as well as 2 vectors containing the list of timestamps
		 * and the list of IP addresses (if applicable for the timestamp value type). Blank timestamps or IP addresses
		 * (meaning zeroed values - timestamp=0 or IP address=0.0.0.0) will not be added to the lists. If some error
		 * occurs during the parsing or the value is invalid an empty result is returned
		 * @return A structured containing the IPv4 timestamp value
		 */
		IPv4TimestampOptionValue getTimestampOptionValue() const
		{
			IPv4TimestampOptionValue res;
			res.clear();

			if (m_Data == nullptr)
				return res;

			if (getIPv4OptionType() != IPV4OPT_Timestamp)
				return res;

			size_t dataSize = getDataSize();
			if (dataSize < 2)
				return res;

			res.type = static_cast<IPv4TimestampOptionValue::TimestampType>(m_Data->recordValue[1]);

			uint8_t valueOffset = static_cast<uint8_t>(2);
			bool readIPAddr = (res.type == IPv4TimestampOptionValue::TimestampAndIP);

			while (static_cast<size_t>(valueOffset) < dataSize)
			{
				uint32_t curValue;
				memcpy(&curValue, m_Data->recordValue + valueOffset, sizeof(uint32_t));
				if (curValue == 0)
					break;

				if (readIPAddr)
					res.ipAddresses.push_back(IPv4Address(curValue));
				else
					res.timestamps.push_back(curValue);

				if (res.type == IPv4TimestampOptionValue::TimestampAndIP)
					readIPAddr = !readIPAddr;

				valueOffset += static_cast<uint8_t>(4);
			}

			return res;
		}

		/**
		 * @return IPv4 option type casted as vanhooks::net::IPv4OptionTypes enum
		 */
		IPv4OptionTypes getIPv4OptionType() const
		{
			return getIPv4OptionType(m_Data);
		}

		/**
		 * Check if a pointer can be assigned to the TLV record data
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 * @param[in] tlvDataLen The size of the TLV record raw data
		 * @return True if data is valid and can be assigned
		 */
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			auto data = reinterpret_cast<TLVRawData const*>(recordRawData);
			if (data == nullptr)
				return false;

			if (tlvDataLen < sizeof(TLVRawData::recordType))
				return false;

			if (getIPv4OptionType(data) == static_cast<uint8_t>(IPV4OPT_EndOfOptionsList) ||
			    data->recordType == static_cast<uint8_t>(IPV4OPT_NOP))
				return true;

			return TLVRecord<uint8_t, uint8_t>::canAssign(recordRawData, tlvDataLen);
		}

		// implement abstract methods

		size_t getTotalSize() const
		{
			if (m_Data == nullptr)
				return 0;

			if (getIPv4OptionType() == static_cast<uint8_t>(IPV4OPT_EndOfOptionsList) ||
			    m_Data->recordType == static_cast<uint8_t>(IPV4OPT_NOP))
				return sizeof(uint8_t);

			return static_cast<size_t>(m_Data->recordLen);
		}

		size_t getDataSize() const
		{
			if (m_Data == nullptr)
				return 0;

			if (getIPv4OptionType() == static_cast<uint8_t>(IPV4OPT_EndOfOptionsList) ||
			    m_Data->recordType == static_cast<uint8_t>(IPV4OPT_NOP))
				return 0;

			return static_cast<size_t>(m_Data->recordLen) - (2 * sizeof(uint8_t));
		}

	private:
		/**
		 * @return IPv4 option type casted as vanhooks::net::IPv4OptionTypes enum
		 */
		static IPv4OptionTypes getIPv4OptionType(const TLVRawData* data)
		{
			if (data == nullptr)
				return IPV4OPT_Unknown;

			return static_cast<IPv4OptionTypes>(data->recordType);
		}
	};

	/**
	 * @class IPv4OptionBuilder
	 * A class for building IPv4 option records. This builder receives the IPv4 option parameters in its c'tor,
	 * builds the IPv4 option raw buffer and provides a build() method to get a IPv4Option object out of it
	 */
	class IPv4OptionBuilder : public TLVRecordBuilder
	{
	private:
		bool m_BuilderParamsValid;

	public:
		/**
		 * A c'tor for building IPv4 options which their value is a byte array. The IPv4Option object can be later
		 * retrieved by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		 * any way. For option types ::IPV4OPT_NOP and ::IPV4OPT_EndOfOptionsList this parameter is ignored (expected to
		 * be nullptr) as these option types don't contain any data
		 * @param[in] optionValueLen Option value length in bytes
		 */
		IPv4OptionBuilder(IPv4OptionTypes optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen)
		{
			m_BuilderParamsValid = true;
		}

		/**
		 * A c'tor for building IPv4 options which have a 2-byte value. The IPv4Option object can be later retrieved
		 * by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] optionValue A 2-byte option value
		 */
		IPv4OptionBuilder(IPv4OptionTypes optionType, uint16_t optionValue)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue)
		{
			m_BuilderParamsValid = true;
		}

		/**
		 * A c'tor for building IPv4 options which their value is a list of IPv4 addresses, for example:
		 * ::IPV4OPT_RecordRoute, ::IPV4OPT_StrictSourceRoute, ::IPV4OPT_LooseSourceRoute. The IPv4Option object can be
		 * later retrieved by calling build()
		 * @param[in] optionType IPv4 option type
		 * @param[in] ipList A vector of IPv4 addresses that will be used as the option value
		 */
		IPv4OptionBuilder(IPv4OptionTypes optionType, const std::vector<IPv4Address>& ipList);

		/**
		 * A c'tor for building IPv4 timestamp option (::IPV4OPT_Timestamp). The IPv4Option object can be later
		 * retrieved by calling build()
		 * @param[in] timestampValue The timestamp value to build the IPv4 option with
		 */
		explicit IPv4OptionBuilder(const IPv4TimestampOptionValue& timestampValue);

		/**
		 * Build the IPv4Option object out of the parameters defined in the c'tor
		 * @return The IPv4Option object
		 */
		IPv4Option build() const;
	};

	/**
	 * @class IPv4Layer
	 * Represents an IPv4 protocol layer
	 */
	class IPv4Layer : public Layer, public IPLayer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref iphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref iphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @param[in] setTotalLenAsDataLen When setting this value to "true" or when using the other c'tor, the layer
		 * data length is calculated from iphdr#totalLength field. When setting to "false" the data length is set as the
		 * value of dataLen parameter. Please notice that if iphdr#totalLength is equal to zero (which can happen in TCP
		 * Segmentation Offloading), this flag is ignored and the layer data length is calculated by the actual data
		 * captured on the wire
		 */
		IPv4Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, bool setTotalLenAsDataLen);

		/**
		 * A constructor that allocates a new IPv4 header with empty fields
		 */
		IPv4Layer();

		/**
		 * A constructor that allocates a new IPv4 header with source and destination IPv4 addresses
		 * @param[in] srcIP Source IPv4 address
		 * @param[in] dstIP Destination IPv4 address
		 */
		IPv4Layer(const IPv4Address& srcIP, const IPv4Address& dstIP);

		/**
		 * A copy constructor that copy the entire header from the other IPv4Layer (including IPv4 options)
		 */
		IPv4Layer(const IPv4Layer& other);

		/**
		 * An assignment operator that first delete all data from current layer and then copy the entire header from the
		 * other IPv4Layer (including IPv4 options)
		 */
		IPv4Layer& operator=(const IPv4Layer& other);

		/**
		 * Get a pointer to the IPv4 header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the @ref iphdr
		 */
		iphdr* getIPv4Header() const
		{
			return (iphdr*)m_Data;
		}

		/**
		 * Get the source IP address in the form of IPAddress. This method is very similar to getSrcIPv4Address(),
		 * but adds a level of abstraction because IPAddress can be used for both IPv4 and IPv6 addresses
		 * @return An IPAddress containing the source address
		 */
		IPAddress getSrcIPAddress() const
		{
			return getSrcIPv4Address();
		}

		/**
		 * Get the source IP address in the form of IPv4Address
		 * @return An IPv4Address containing the source address
		 */
		IPv4Address getSrcIPv4Address() const
		{
			return getIPv4Header()->ipSrc;
		}

		/**
		 * Set the source IP address
		 * @param[in] ipAddr The IP address to set
		 */
		void setSrcIPv4Address(const IPv4Address& ipAddr)
		{
			getIPv4Header()->ipSrc = ipAddr.toInt();
		}

		/**
		 * Get the destination IP address in the form of IPAddress. This method is very similar to getDstIPv4Address(),
		 * but adds a level of abstraction because IPAddress can be used for both IPv4 and IPv6 addresses
		 * @return An IPAddress containing the destination address
		 */
		IPAddress getDstIPAddress() const
		{
			return getDstIPv4Address();
		}

		/**
		 * Get the destination IP address in the form of IPv4Address
		 * @return An IPv4Address containing the destination address
		 */
		IPv4Address getDstIPv4Address() const
		{
			return getIPv4Header()->ipDst;
		}

		/**
		 * Set the dest IP address
		 * @param[in] ipAddr The IP address to set
		 */
		void setDstIPv4Address(const IPv4Address& ipAddr)
		{
			getIPv4Header()->ipDst = ipAddr.toInt();
		}

		/**
		 * @return True if this packet is a fragment (in sense of IP fragmentation), false otherwise
		 */
		bool isFragment() const;

		/**
		 * @return True if this packet is a fragment (in sense of IP fragmentation) and is the first fragment
		 * (which usually contains the L4 header). Return false otherwise (not a fragment or not the first fragment)
		 */
		bool isFirstFragment() const;

		/**
		 * @return True if this packet is a fragment (in sense of IP fragmentation) and is the last fragment.
		 * Return false otherwise (not a fragment or not the last fragment)
		 */
		bool isLastFragment() const;

		/**
		 * @return A bitmask containing the fragmentation flags (e.g IP_DONT_FRAGMENT or IP_MORE_FRAGMENTS)
		 */
		uint8_t getFragmentFlags() const;

		/**
		 * @return The fragment offset in case this packet is a fragment, 0 otherwise
		 */
		uint16_t getFragmentOffset() const;

		/**
		 * Get an IPv4 option by type.
		 * @param[in] option IPv4 option type
		 * @return An IPv4Option object that contains the first option that matches this type, or logical null
		 * (IPv4Option#isNull() == true) if no such option found
		 */
		IPv4Option getOption(IPv4OptionTypes option) const;

		/**
		 * @return The first IPv4 option in the packet. If the current layer contains no options the returned value will
		 * contain a logical null (IPv4Option#isNull() == true)
		 */
		IPv4Option getFirstOption() const;

		/**
		 * Get the IPv4 option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical null (IPv4Option#isNull() == true)
		 * @param[in] option An IPv4 option object that exists in the current layer
		 * @return A IPv4Option object that contains the IPv4 option data that comes next, or logical null if the
		 * given IPv4 option: (1) was the last one; or (2) contains a logical null; or (3) doesn't belong to this
		 * packet
		 */
		IPv4Option getNextOption(IPv4Option& option) const;

		/**
		 * @return The number of IPv4 options in this layer
		 */
		size_t getOptionCount() const;

		/**
		 * Add a new IPv4 option at the end of the layer (after the last IPv4 option)
		 * @param[in] optionBuilder An IPv4OptionBuilder object that contains the IPv4 option data to be added
		 * @return A IPv4Option object that contains the newly added IPv4 option data or logical null
		 * (IPv4Option#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		IPv4Option addOption(const IPv4OptionBuilder& optionBuilder);

		/**
		 * Add a new IPv4 option after an existing one
		 * @param[in] optionBuilder An IPv4OptionBuilder object that contains the requested IPv4 option data to be added
		 * @param[in] prevOptionType The IPv4 option which the newly added option should come after. This is an optional
		 * parameter which gets a default value of ::IPV4OPT_Unknown if omitted, which means the new option will be
		 * added as the first option in the layer
		 * @return A IPv4Option object containing the newly added IPv4 option data or logical null
		 * (IPv4Option#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		IPv4Option addOptionAfter(const IPv4OptionBuilder& optionBuilder,
		                          IPv4OptionTypes prevOptionType = IPV4OPT_Unknown);

		/**
		 * Remove an IPv4 option
		 * @param[in] option The option type to remove
		 * @return True if option was removed successfully or false if option type wasn't found or failed to shorten the
		 * layer. If an option appears twice in the layer, its first instance will be removed
		 */
		bool removeOption(IPv4OptionTypes option);

		/**
		 * Remove all IPv4 options from the layer
		 * @return True if options removed successfully or false if some error occurred (an appropriate error message
		 * will be printed to log)
		 */
		bool removeAllOptions();

		// implement abstract methods

		/**
		 * Currently identifies the following next layers:
		 * - UdpLayer
		 * - TcpLayer
		 * - IcmpLayer
		 * - IPv4Layer (IP-in-IP)
		 * - IPv6Layer (IP-in-IP)
		 * - GreLayer
		 * - IgmpLayer
		 * - AuthenticationHeaderLayer (IPSec)
		 * - ESPLayer (IPSec)
		 *
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of IPv4 header (including IPv4 options if exist)
		 */
		size_t getHeaderLen() const
		{
			return static_cast<size_t>(static_cast<uint16_t>(getIPv4Header()->internetHeaderLength) * 4) +
			       m_TempHeaderExtension;
		}

		/**
		 * Calculate the following fields:
		 * - iphdr#ipVersion = 4;
		 * - iphdr#totalLength = total packet length
		 * - iphdr#headerChecksum = calculated
		 * - iphdr#protocol = calculated if next layer is known: ::PACKETPP_IPPROTO_TCP for TCP, ::PACKETPP_IPPROTO_UDP
		 * for UDP, ::PACKETPP_IPPROTO_ICMP for ICMP
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of IP packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an IPv4 packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

	private:
		int m_NumOfTrailingBytes;
		int m_TempHeaderExtension;
		TLVRecordReader<IPv4Option> m_OptionReader;

		void copyLayerData(const IPv4Layer& other);
		uint8_t* getOptionsBasePtr() const
		{
			return m_Data + sizeof(iphdr);
		}
		IPv4Option addOptionAt(const IPv4OptionBuilder& optionBuilder, int offset);
		void adjustOptionsTrailer(size_t totalOptSize);
		void initLayer();
		void initLayerInPacket(bool setTotalLenAsDataLen);
	};

	// implementation of inline methods

	bool IPv4Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		const iphdr* hdr = reinterpret_cast<const iphdr*>(data);
		return dataLen >= sizeof(iphdr) && hdr->ipVersion == 4 && hdr->internetHeaderLength >= 5;
	}

}  // namespace vanhooks::net
// ---- end IPv4Layer.h ----

// ---- begin IPv6Extensions.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class IPv6Extension
	 * A base class for all supported IPv6 extensions. This class is abstract, meaning it cannot be instantiated or
	 * copied (has private c'tor and copy c'tor)
	 */
	class IPv6Extension
	{
		friend class IPv6Layer;

	public:
		/**
		 * An enum representing all supported IPv6 extension types
		 */
		enum IPv6ExtensionType
		{
			/** Hop-By-Hop extension type */
			IPv6HopByHop = 0,
			/** Routing extension type */
			IPv6Routing = 43,
			/** IPv6 fragmentation extension type */
			IPv6Fragmentation = 44,
			/** Authentication Header extension type */
			IPv6AuthenticationHdr = 51,
			/** Destination extension type */
			IPv6Destination = 60,
			/** Unknown or unsupported extension type */
			IPv6ExtensionUnknown = 255
		};

		/**
		 * @return The size of extension in bytes, meaning (for most extensions): 8 * ([headerLen field] + 1)
		 */
		virtual size_t getExtensionLen() const
		{
			return 8 * (getBaseHeader()->headerLen + 1);
		}

		/**
		 * @return The type of the extension
		 */
		IPv6ExtensionType getExtensionType() const
		{
			return m_ExtType;
		}

		/**
		 * A destructor for this class
		 */
		virtual ~IPv6Extension();

		/**
		 * @return A pointer to the next header or nullptr if the extension is the last one
		 */
		IPv6Extension* getNextHeader() const
		{
			return m_NextHeader;
		}

	protected:
		struct ipv6_ext_base_header
		{
			uint8_t nextHeader;
			uint8_t headerLen;
		};

		// protected c'tor
		IPv6Extension(IDataContainer* dataContainer, size_t offset)
		    : m_NextHeader(nullptr), m_ExtType(IPv6ExtensionUnknown), m_DataContainer(dataContainer), m_Offset(offset),
		      m_ShadowData(nullptr)
		{}

		// protected empty c'tor
		IPv6Extension()
		    : m_NextHeader(nullptr), m_ExtType(IPv6ExtensionUnknown), m_DataContainer(nullptr), m_Offset(0),
		      m_ShadowData(nullptr)
		{}

		// protected assignment operator
		IPv6Extension& operator=(const IPv6Extension& other);

		uint8_t* getDataPtr() const;

		void initShadowPtr(size_t size);

		ipv6_ext_base_header* getBaseHeader() const
		{
			return (ipv6_ext_base_header*)getDataPtr();
		}

		void setNextHeader(IPv6Extension* nextHeader)
		{
			m_NextHeader = nextHeader;
		}

		IPv6Extension* m_NextHeader;
		IPv6ExtensionType m_ExtType;

	private:
		IDataContainer* m_DataContainer;
		size_t m_Offset;
		uint8_t* m_ShadowData;
	};

	/**
	 * @class IPv6FragmentationHeader
	 * Represents an IPv6 fragmentation extension header and allows easy access to all fragmentation parameters
	 */
	class IPv6FragmentationHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:
		/**
		 * @struct ipv6_frag_header
		 * A struct representing IPv6 fragmentation header
		 */
		struct ipv6_frag_header
		{
			/** Next header type */
			uint8_t nextHeader;
			/** Fragmentation header size is fixed 8 bytes, so len is always zero */
			uint8_t headerLen;
			/** Offset, in 8-octet units, relative to the start of the fragmentable part of the original packet
			 * plus 1-bit indicating if more fragments will follow */
			uint16_t fragOffsetAndFlags;
			/** packet identification value. Needed for reassembly of the original packet */
			uint32_t id;
		};

		/**
		 * A c'tor for creating a new IPv6 fragmentation extension object not bounded to a packet. Useful for adding new
		 * extensions to an IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] fragId Fragmentation ID
		 * @param[in] fragOffset Fragmentation offset
		 * @param[in] lastFragment Indicates whether this fragment is the last one
		 */
		IPv6FragmentationHeader(uint32_t fragId, uint16_t fragOffset, bool lastFragment);

		/**
		 * Get a pointer to the fragmentation header. Notice the returned pointer points directly to the data, so every
		 * change will modify the actual packet data
		 * @return A pointer to the @ref ipv6_frag_header
		 */
		ipv6_frag_header* getFragHeader() const
		{
			return (ipv6_frag_header*)getDataPtr();
		}

		/**
		 * @return True if this is the first fragment (which usually contains the L4 header), false otherwise
		 */
		bool isFirstFragment() const;

		/**
		 * @return True if this is the last fragment, false otherwise
		 */
		bool isLastFragment() const;

		/**
		 * @return True if the "more fragments" bit is set, meaning more fragments are expected to follow this fragment
		 */
		bool isMoreFragments() const;

		/**
		 * @return The fragment offset
		 */
		uint16_t getFragmentOffset() const;

	private:
		IPv6FragmentationHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset)
		{
			m_ExtType = IPv6Fragmentation;
		}
	};

	/**
	 * An abstract base class for Hop-By-Hop and Destination IPv6 extensions which their structure contains
	 * Type-Length-Value (TLV) options. This class provides access to these options and their data as well as methods to
	 * create new options. Notice this class is abstract and cannot be instantiated
	 */
	class IPv6TLVOptionHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:
		/**
		 * @class IPv6Option
		 * A class representing a Type-Length-Value (TLV) options that are used inside Hop-By-Hop and Destinations IPv6
		 * extensions. This class does not create or modify IPv6 option records, but rather serves as a wrapper and
		 * provides useful methods for retrieving data from them
		 */
		class IPv6Option : public TLVRecord<uint8_t, uint8_t>
		{
		public:
			static const uint8_t Pad0OptionType = 0;
			static const uint8_t PadNOptionType = 1;

			/**
			 * A c'tor for this class that gets a pointer to the option raw data (byte array)
			 * @param[in] optionRawData A pointer to the attribute raw data
			 */
			explicit IPv6Option(uint8_t* optionRawData) : TLVRecord(optionRawData)
			{}

			/**
			 * A d'tor for this class, currently does nothing
			 */
			~IPv6Option()
			{}

			/**
			 * Check if a pointer can be assigned to the TLV record data
			 * @param[in] recordRawData A pointer to the TLV record raw data
			 * @param[in] tlvDataLen The size of the TLV record raw data
			 * @return True if data is valid and can be assigned
			 */
			static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
			{
				auto data = (TLVRawData*)recordRawData;
				if (data == nullptr)
					return false;

				if (tlvDataLen < sizeof(TLVRawData::recordType))
					return false;

				if (data->recordType == Pad0OptionType)
					return true;

				return TLVRecord<uint8_t, uint8_t>::canAssign(recordRawData, tlvDataLen);
			}

			// implement abstract methods

			size_t getTotalSize() const
			{
				if (m_Data == nullptr)
					return 0;

				if (m_Data->recordType == Pad0OptionType)
					return sizeof(uint8_t);

				return (size_t)(m_Data->recordLen + sizeof(uint16_t));
			}

			size_t getDataSize() const
			{
				if (m_Data == nullptr || m_Data->recordType == Pad0OptionType)
					return 0;

				return (size_t)m_Data->recordLen;
			}
		};

		/**
		 * @class IPv6TLVOptionBuilder
		 * A class for building IPv6 Type-Length-Value (TLV) options. This builder receives the option parameters in its
		 * c'tor, builds the option raw buffer and provides a method to build a IPv6Option object out of it
		 */
		class IPv6TLVOptionBuilder : public TLVRecordBuilder
		{
		public:
			/**
			 * A c'tor for building IPv6 TLV options which their value is a byte array. The IPv6Option object can later
			 * be retrieved by calling build()
			 * @param[in] optType IPv6 option type
			 * @param[in] optValue A buffer containing the option value. This buffer is read-only and isn't modified in
			 * any way
			 * @param[in] optValueLen Option value length in bytes
			 */
			IPv6TLVOptionBuilder(uint8_t optType, const uint8_t* optValue, uint8_t optValueLen)
			    : TLVRecordBuilder(optType, optValue, optValueLen)
			{}

			/**
			 * A c'tor for building IPv6 TLV options which have a 1-byte value. The IPv6Option object can later be
			 * retrieved by calling build()
			 * @param[in] optType IPv6 option type
			 * @param[in] optValue A 1-byte option value
			 */
			IPv6TLVOptionBuilder(uint8_t optType, uint8_t optValue) : TLVRecordBuilder(optType, optValue)
			{}

			/**
			 * A c'tor for building IPv6 TLV options which have a 2-byte value. The IPv6Option object can later be
			 * retrieved by calling build()
			 * @param[in] optType IPv6 option type
			 * @param[in] optValue A 2-byte option value
			 */
			IPv6TLVOptionBuilder(uint8_t optType, uint16_t optValue) : TLVRecordBuilder(optType, optValue)
			{}

			/**
			 * A copy c'tor that creates an instance of this class out of another instance and copies all the data from
			 * it
			 * @param[in] other The instance to copy data from
			 */
			IPv6TLVOptionBuilder(const IPv6TLVOptionBuilder& other) : TLVRecordBuilder(other)
			{}

			/**
			 * Assignment operator that copies all data from another instance of IPv6TLVOptionBuilder
			 * @param[in] other The instance to assign from
			 */
			IPv6TLVOptionBuilder& operator=(const IPv6TLVOptionBuilder& other)
			{
				TLVRecordBuilder::operator=(other);
				return *this;
			}

			/**
			 * Build the IPv6Option object out of the parameters defined in the c'tor
			 * @return The IPv6Option object
			 */
			IPv6Option build() const;
		};

		/**
		 * Retrieve an option by its type
		 * @param[in] optionType Option type
		 * @return An IPv6Option object that wraps the option data. If option isn't found a logical null is returned
		 * (IPv6Option#isNull() == true)
		 */
		IPv6Option getOption(uint8_t optionType) const;

		/**
		 * @return An IPv6Option that wraps the first option data or logical null (IPv6Option#isNull() == true) if no
		 * options exist
		 */
		IPv6Option getFirstOption() const;

		/**
		 * Returns a pointer to the option that comes after the option given as the parameter
		 * @param[in] option A pointer to an option instance
		 * @return An IPv6Option object that wraps the option data. In the following cases logical null
		 * (IPv6Option#isNull() == true) is returned: (1) input parameter is out-of-bounds for this extension or (2) the
		 * next option doesn't exist or (3) the input option is nullptr
		 */
		IPv6Option getNextOption(IPv6Option& option) const;

		/**
		 * @returns The number of options this IPv6 extension contains
		 */
		size_t getOptionCount() const;

	protected:
		/** A private c'tor to keep this object from being constructed */
		explicit IPv6TLVOptionHeader(const std::vector<IPv6TLVOptionBuilder>& options);

		IPv6TLVOptionHeader(IDataContainer* dataContainer, size_t offset);

	private:
		TLVRecordReader<IPv6Option> m_OptionReader;
	};

	/**
	 * @class IPv6HopByHopHeader
	 * Represents IPv6 Hop-By-Hop extension header and allows easy access to all of its data including the TLV options
	 * stored
	 */
	class IPv6HopByHopHeader : public IPv6TLVOptionHeader
	{
		friend class IPv6Layer;

	public:
		/**
		 * A c'tor for creating a new IPv6 Hop-By-Hop extension object not bounded to a packet. Useful for adding new
		 * extensions to an IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] options A vector of IPv6TLVOptionHeader#TLVOptionBuilder instances which define the options that
		 * will be stored in the extension data. Notice this vector is read-only and its content won't be modified
		 */
		explicit IPv6HopByHopHeader(const std::vector<IPv6TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options)
		{
			m_ExtType = IPv6HopByHop;
		}

	private:
		IPv6HopByHopHeader(IDataContainer* dataContainer, size_t offset) : IPv6TLVOptionHeader(dataContainer, offset)
		{
			m_ExtType = IPv6HopByHop;
		}
	};

	/**
	 * @class IPv6DestinationHeader
	 * Represents IPv6 destination extension header and allows easy access to all of its data including the TLV options
	 * stored in it
	 */
	class IPv6DestinationHeader : public IPv6TLVOptionHeader
	{
		friend class IPv6Layer;

	public:
		/**
		 * A c'tor for creating a new IPv6 destination extension object not bounded to a packet. Useful for adding new
		 * extensions to an IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] options A vector of IPv6TLVOptionHeader#TLVOptionBuilder instances which define the options that
		 * will be stored in the extension data. Notice this vector is read-only and its content won't be modified
		 */
		explicit IPv6DestinationHeader(const std::vector<IPv6TLVOptionBuilder>& options) : IPv6TLVOptionHeader(options)
		{
			m_ExtType = IPv6Destination;
		}

	private:
		IPv6DestinationHeader(IDataContainer* dataContainer, size_t offset) : IPv6TLVOptionHeader(dataContainer, offset)
		{
			m_ExtType = IPv6Destination;
		}
	};

	/**
	 * @class IPv6RoutingHeader
	 * Represents IPv6 routing extension header and allows easy access to all of its data
	 */
	class IPv6RoutingHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:
		/**
		 * @struct ipv6_routing_header
		 * A struct representing the fixed part of the IPv6 routing extension header
		 */
		struct ipv6_routing_header
		{
			/** Next header type */
			uint8_t nextHeader;
			/** The length of this header, in multiples of 8 octets, not including the first 8 octets */
			uint8_t headerLen;
			/** A value representing the routing type */
			uint8_t routingType;
			/** Number of nodes this packet still has to visit before reaching its final destination */
			uint8_t segmentsLeft;
		};

		/**
		 * A c'tor for creating a new IPv6 routing extension object not bounded to a packet. Useful for adding new
		 * extensions to an IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] routingType Routing type value (will be written to ipv6_routing_header#routingType field)
		 * @param[in] segmentsLeft Segments left value (will be written to ipv6_routing_header#segmentsLeft field)
		 * @param[in] additionalRoutingData A pointer to a buffer containing the additional routing data for this
		 * extension. Notice this buffer is read-only and its content isn't modified
		 * @param[in] additionalRoutingDataLen The length of the additional routing data buffer
		 */
		IPv6RoutingHeader(uint8_t routingType, uint8_t segmentsLeft, const uint8_t* additionalRoutingData,
		                  size_t additionalRoutingDataLen);

		/**
		 * Get a pointer to the fixed part of the routing header. Notice the return pointer points directly to the data,
		 * so every change will modify the actual packet data
		 * @return A pointer to the @ref ipv6_routing_header
		 */
		ipv6_routing_header* getRoutingHeader() const
		{
			return (ipv6_routing_header*)getDataPtr();
		}

		/**
		 * @return A pointer to the buffer containing the additional routing data for this extension. Notice that any
		 * change in this buffer will lead to a change in the extension data
		 */
		uint8_t* getRoutingAdditionalData() const;

		/**
		 * @return The length of the additional routing parameters buffer
		 */
		size_t getRoutingAdditionalDataLength() const;

		/**
		 * In many cases the additional routing data is actually IPv6 address(es). This method converts the raw buffer
		 * data into an IPv6 address
		 * @param[in] offset An offset in the additional routing buffer pointing to where the IPv6 address begins. In
		 * some cases there are multiple IPv6 addresses in the additional routing data buffer so this offset points to
		 * where the request IPv6 address begins. Also, even if there is only one IPv6 address in this buffer, sometimes
		 * it isn't written in the beginning of the buffer, so the offset points to where the IPv6 address begins. This
		 * is an optional parameter and the default offset is 0
		 * @return The IPv6 address stored in the additional routing data buffer from the offset defined by the user. If
		 * offset is out-of-bounds of the extension of doesn't have 16 bytes (== the length of IPv6 address) until the
		 * end of the buffer - IPv6Address#Zero is returned
		 */
		IPv6Address getRoutingAdditionalDataAsIPv6Address(size_t offset = 0) const;

	private:
		IPv6RoutingHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset)
		{
			m_ExtType = IPv6Routing;
		}
	};

	/**
	 * @class IPv6AuthenticationHeader
	 * Represents IPv6 authentication header extension (used in IPSec protocol) and allows easy access to all of its
	 * data
	 */
	class IPv6AuthenticationHeader : public IPv6Extension
	{
		friend class IPv6Layer;

	public:
		/**
		 * @struct ipv6_authentication_header
		 * A struct representing the fixed part of the IPv6 authentication header extension
		 */
		struct ipv6_authentication_header
		{
			/** Next header type */
			uint8_t nextHeader;
			/** The length of this Authentication Header in 4-octet units, minus 2. For example, an AH value of 4
			 * equals: [ 3×(32-bit fixed-length AH fields) + 3×(32-bit ICV fields) − 2 ] and thus an AH value of 4 means
			 * 24 octets */
			uint8_t headerLen;
			/** Reserved bytes, all zeros */
			uint16_t reserved;
			/** Arbitrary value which is used (together with the destination IP address) to identify the security
			 * association of the receiving party */
			uint32_t securityParametersIndex;
			/** A monotonic strictly increasing sequence number (incremented by 1 for every packet sent) */
			uint32_t sequenceNumber;
		};

		/**
		 * A c'tor for creating a new IPv6 authentication header extension object not bounded to a packet. Useful for
		 * adding new extensions to an IPv6 layer with IPv6Layer#addExtension()
		 * @param[in] securityParametersIndex Security Parameters Index (SPI) value (will be written to
		 * ipv6_authentication_header#securityParametersIndex field)
		 * @param[in] sequenceNumber Sequence number value (will be written to ipv6_authentication_header#sequenceNumber
		 * field)
		 * @param[in] integrityCheckValue A pointer to a buffer containing the integrity check value (ICV) data for this
		 * extension. Notice this pointer is read-only and its content isn't modified in any way
		 * @param[in] integrityCheckValueLen The length of the integrity check value (ICV) buffer
		 */
		IPv6AuthenticationHeader(uint32_t securityParametersIndex, uint32_t sequenceNumber,
		                         const uint8_t* integrityCheckValue, size_t integrityCheckValueLen);

		/**
		 * Get a pointer to the fixed part of the authentication header. Notice the return pointer points directly to
		 * the data, so every change will modify the actual packet data
		 * @return A pointer to the @ref ipv6_authentication_header
		 */
		ipv6_authentication_header* getAuthHeader() const
		{
			return (ipv6_authentication_header*)getDataPtr();
		}

		/**
		 * @return A pointer to the buffer containing the integrity check value (ICV) for this extension. Notice that
		 * any change in this buffer will lead to a change in the extension data
		 */
		uint8_t* getIntegrityCheckValue() const;

		/**
		 * @return The length of the integrity check value (ICV) buffer
		 */
		size_t getIntegrityCheckValueLength() const;

		// overridden methods

		/**
		 * In the authentication header the extension length is calculated in a different way than other extensions. The
		 * calculation is: [ 4 * (ipv6_authentication_header#headerLen + 2) ]
		 * @return The length of this extension
		 */
		size_t getExtensionLen() const
		{
			return 4 * (getBaseHeader()->headerLen + 2);
		}

	private:
		IPv6AuthenticationHeader(IDataContainer* dataContainer, size_t offset) : IPv6Extension(dataContainer, offset)
		{
			m_ExtType = IPv6AuthenticationHdr;
		}
	};

}  // namespace vanhooks::net
// ---- end IPv6Extensions.h ----

// ---- begin IPv6Layer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct ip6_hdr
	 * Represents IPv6 protocol header
	 */
#pragma pack(push, 1)
	struct ip6_hdr
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Traffic class */
		uint8_t trafficClass : 4,
		    /** IP version number, has the value of 6 for IPv6 */
		    ipVersion : 4;
#else
		/** IP version number, has the value of 6 for IPv6 */
		uint8_t ipVersion : 4,
		    /** Traffic class */
		    trafficClass : 4;
#endif
		/** Flow label */
		uint8_t flowLabel[3];
		/** The size of the payload in octets, including any extension headers */
		uint16_t payloadLength;
		/** Specifies the type of the next header (protocol). Must be one of ::IPProtocolTypes */
		uint8_t nextHeader;
		/** Replaces the time to live field of IPv4 */
		uint8_t hopLimit;
		/** Source address */
		uint8_t ipSrc[16];
		/** Destination address */
		uint8_t ipDst[16];
	};
#pragma pack(pop)

	/**
	 * @class IPv6Layer
	 * Represents an IPv6 protocol layer
	 */
	class IPv6Layer : public Layer, public IPLayer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref ip6_hdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IPv6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new IPv6 header with empty fields
		 */
		IPv6Layer();

		/**
		 * A constructor that allocates a new IPv6 header with source and destination IPv6 addresses
		 * @param[in] srcIP Source IPv6 address
		 * @param[in] dstIP Destination IPv6 address
		 */
		IPv6Layer(const IPv6Address& srcIP, const IPv6Address& dstIP);

		/**
		 * A copy constructor that copies the entire header from the other IPv6Layer (including IPv6 extensions)
		 */
		IPv6Layer(const IPv6Layer& other);

		/**
		 * A destructor for this layer
		 */
		~IPv6Layer();

		/**
		 * An assignment operator that first delete all data from current layer and then copy the entire header from the
		 * other IPv6Layer (including IPv6 extensions)
		 */
		IPv6Layer& operator=(const IPv6Layer& other);

		/**
		 * Get a pointer to the IPv6 header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the @ref ip6_hdr
		 */
		ip6_hdr* getIPv6Header() const
		{
			return (ip6_hdr*)m_Data;
		}

		/**
		 * Get the source IP address in the form of IPAddress. This method is very similar to getSrcIPv6Address(),
		 * but adds a level of abstraction because IPAddress can be used for both IPv4 and IPv6 addresses
		 * @return An IPAddress containing the source address
		 */
		IPAddress getSrcIPAddress() const
		{
			return getSrcIPv6Address();
		}

		/**
		 * Get the source IP address in the form of IPv6Address
		 * @return An IPv6Address containing the source address
		 */
		IPv6Address getSrcIPv6Address() const
		{
			return getIPv6Header()->ipSrc;
		}

		/**
		 * Set the source IP address
		 * @param[in] ipAddr The IP address to set
		 */
		void setSrcIPv6Address(const IPv6Address& ipAddr)
		{
			ipAddr.copyTo(getIPv6Header()->ipSrc);
		}

		/**
		 * Set the dest IP address
		 * @param[in] ipAddr The IP address to set
		 */
		void setDstIPv6Address(const IPv6Address& ipAddr)
		{
			ipAddr.copyTo(getIPv6Header()->ipDst);
		}

		/**
		 * Get the destination IP address in the form of IPAddress. This method is very similar to getDstIPv6Address(),
		 * but adds a level of abstraction because IPAddress can be used for both IPv4 and IPv6 addresses
		 * @return An IPAddress containing the destination address
		 */
		IPAddress getDstIPAddress() const
		{
			return getDstIPv6Address();
		}

		/**
		 * Get the destination IP address in the form of IPv6Address
		 * @return An IPv6Address containing the destination address
		 */
		IPv6Address getDstIPv6Address() const
		{
			return getIPv6Header()->ipDst;
		}

		/**
		 * @return Number of IPv6 extensions in this layer
		 */
		size_t getExtensionCount() const;

		/**
		 * A templated getter for an IPv6 extension of a type TIPv6Extension. TIPv6Extension has to be one of the
		 * supported IPv6 extensions, meaning a class that inherits IPv6Extension. If the requested extension type isn't
		 * found nullptr is returned
		 * @return A pointer to the extension instance or nullptr if the requested extension type isn't found
		 */
		template <class TIPv6Extension> TIPv6Extension* getExtensionOfType() const;

		/**
		 * Add a new extension of type TIPv6Extension to the layer. This is a templated method and TIPv6Extension has to
		 * be one of the supported IPv6 extensions, meaning a class that inherits IPv6Extension. If the extension is
		 * added successfully a pointer to the newly added extension object is returned, otherwise nullptr is returned
		 * @param[in] extensionHeader The extension object to add. Notice the object passed here is read-only, meaning
		 * its data is copied but the object itself isn't modified
		 * @return If the extension is added successfully a pointer to the newly added extension object is returned.
		 * Otherwise nullptr is returned
		 */
		template <class TIPv6Extension> TIPv6Extension* addExtension(const TIPv6Extension& extensionHeader);

		/**
		 * Remove all IPv6 extensions in this layer
		 */
		void removeAllExtensions();

		/**
		 * @return True if this packet is an IPv6 fragment, meaning if it has an IPv6FragmentationHeader extension
		 */
		bool isFragment() const;

		/**
		 * The static method makes validation of input data
		 * @param[in] data The pointer to the beginning of byte stream of IP packet
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent the IPv6 packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers:
		 * - UdpLayer
		 * - TcpLayer
		 * - IPv4Layer (IP-in-IP)
		 * - IPv6Layer (IP-in-IP)
		 * - GreLayer
		 * - AuthenticationHeaderLayer (IPSec)
		 * - ESPLayer (IPSec)
		 *
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of @ref ip6_hdr
		 */
		size_t getHeaderLen() const
		{
			return sizeof(ip6_hdr) + m_ExtensionsLen;
		}

		/**
		 * Calculate the following fields:
		 * - ip6_hdr#payloadLength = size of payload (all data minus header size)
		 * - ip6_hdr#ipVersion = 6
		 * - ip6_hdr#nextHeader = calculated if next layer is known: ::PACKETPP_IPPROTO_TCP for TCP,
		 * ::PACKETPP_IPPROTO_UDP for UDP, ::PACKETPP_IPPROTO_ICMP for ICMP
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}

	private:
		void initLayer();
		void parseExtensions();
		void deleteExtensions();

		IPv6Extension* m_FirstExtension;
		IPv6Extension* m_LastExtension;
		size_t m_ExtensionsLen;
	};

	template <class TIPv6Extension> TIPv6Extension* IPv6Layer::getExtensionOfType() const
	{
		IPv6Extension* curExt = m_FirstExtension;
		while (curExt != nullptr && dynamic_cast<TIPv6Extension*>(curExt) == nullptr)
			curExt = curExt->getNextHeader();

		return static_cast<TIPv6Extension*>(curExt);
	}

	template <class TIPv6Extension> TIPv6Extension* IPv6Layer::addExtension(const TIPv6Extension& extensionHeader)
	{
		int offsetToAddHeader = static_cast<int>(getHeaderLen());
		if (!extendLayer(offsetToAddHeader, extensionHeader.getExtensionLen()))
		{
			return nullptr;
		}

		TIPv6Extension* newHeader = new TIPv6Extension(this, static_cast<size_t>(offsetToAddHeader));
		(*newHeader) = extensionHeader;

		if (m_FirstExtension != nullptr)
		{
			newHeader->getBaseHeader()->nextHeader = m_LastExtension->getBaseHeader()->nextHeader;
			m_LastExtension->getBaseHeader()->nextHeader = newHeader->getExtensionType();
			m_LastExtension->setNextHeader(newHeader);
			m_LastExtension = newHeader;
		}
		else
		{
			m_FirstExtension = newHeader;
			m_LastExtension = newHeader;
			newHeader->getBaseHeader()->nextHeader = getIPv6Header()->nextHeader;
			getIPv6Header()->nextHeader = newHeader->getExtensionType();
		}

		m_ExtensionsLen += newHeader->getExtensionLen();

		return newHeader;
	}

	// implementation of inline methods

	bool IPv6Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(ip6_hdr);
	}

}  // namespace vanhooks::net
// ---- end IPv6Layer.h ----

// ---- begin IcmpLayer.h ----
#ifdef _MSC_VER
#	include <Winsock2.h>
#else
#	include <sys/time.h>
#endif
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct icmphdr
	 * Represents ICMP basic protocol header (common for all ICMP message types)
	 */
#pragma pack(push, 1)
	typedef struct icmphdr
	{
		/** message type */
		uint8_t type;
		/** message code */
		uint8_t code;
		/** message checksum */
		uint16_t checksum;
	} icmphdr;
#pragma pack(pop)

	/**
	 * An enum of all supported ICMP message types
	 */
	enum IcmpMessageType
	{
		/** ICMP echo (ping) reply message */
		ICMP_ECHO_REPLY = 0,
		/** ICMP destination unreachable message */
		ICMP_DEST_UNREACHABLE = 3,
		/** ICMP source quench message */
		ICMP_SOURCE_QUENCH = 4,
		/** ICMP redirect message */
		ICMP_REDIRECT = 5,
		/** ICMP echo (ping) request message */
		ICMP_ECHO_REQUEST = 8,
		/** ICMP router advertisement message */
		ICMP_ROUTER_ADV = 9,
		/** ICMP router soliciatation message */
		ICMP_ROUTER_SOL = 10,
		/** ICMP time-to-live excceded message */
		ICMP_TIME_EXCEEDED = 11,
		/** ICMP parameter problem message */
		ICMP_PARAM_PROBLEM = 12,
		/** ICMP timestamp request message */
		ICMP_TIMESTAMP_REQUEST = 13,
		/** ICMP timestamp reply message */
		ICMP_TIMESTAMP_REPLY = 14,
		/** ICMP information request message */
		ICMP_INFO_REQUEST = 15,
		/** ICMP information reply message */
		ICMP_INFO_REPLY = 16,
		/** ICMP address mask request message */
		ICMP_ADDRESS_MASK_REQUEST = 17,
		/** ICMP address mask reply message */
		ICMP_ADDRESS_MASK_REPLY = 18,
		/** ICMP message type unsupported by VanHooks */
		ICMP_UNSUPPORTED = 255
	};

	/**
	 * An enum for all possible codes for a destination unreachable message type
	 * Documentation is taken from Wikipedia: https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
	 */
	enum IcmpDestUnreachableCodes
	{
		/** Network unreachable error */
		IcmpNetworkUnreachable = 0,
		/** Host unreachable error */
		IcmpHostUnreachable = 1,
		/** Protocol unreachable error (the designated transport protocol is not supported) */
		IcmpProtocolUnreachable = 2,
		/** Port unreachable error (the designated protocol is unable to inform the host of the incoming message) */
		IcmpPortUnreachable = 3,
		/** The datagram is too big. Packet fragmentation is required but the 'don't fragment' (DF) flag is on */
		IcmpDatagramTooBig = 4,
		/** Source route failed error */
		IcmpSourceRouteFailed = 5,
		/** Destination network unknown error */
		IcmpDestinationNetworkUnknown = 6,
		/** Destination host unknown error */
		IcmpDestinationHostUnknown = 7,
		/** Source host isolated error */
		IcmpSourceHostIsolated = 8,
		/** The destination network is administratively prohibited */
		IcmpDestinationNetworkProhibited = 9,
		/** The destination host is administratively prohibited */
		IcmpDestinationHostProhibited = 10,
		/** The network is unreachable for Type Of Service */
		IcmpNetworkUnreachableForTypeOfService = 11,
		/** The host is unreachable for Type Of Service */
		IcmpHostUnreachableForTypeOfService = 12,
		/** Communication administratively prohibited (administrative filtering prevents
		 * packet from being forwarded)
		 */
		IcmpCommunicationProhibited = 13,
		/** Host precedence violation (indicates the requested precedence is not permitted for
		 * the combination of host or network and port)
		 */
		IcmpHostPrecedenceViolation = 14,
		/** Precedence cutoff in effect (precedence of datagram is below the level set by
		 * the network administrators)
		 */
		IcmpPrecedenceCutoff = 15
	};

	/**
	 * @struct icmp_echo_hdr
	 * ICMP echo (ping) request/reply message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_echo_hdr : icmphdr
	{
		/** the echo (ping) request identifier */
		uint16_t id;
		/** the echo (ping) request sequence number */
		uint16_t sequence;
		/** a timestamp of when the message was sent */
		uint64_t timestamp;
	} icmp_echo_hdr;
#pragma pack(pop)

	/**
	 * @struct icmp_echo_request
	 * ICMP echo (ping) request/reply message structure
	 */
	typedef struct icmp_echo_request
	{
		/** a pointer to the header data */
		icmp_echo_hdr* header;
		/** most echo requests/replies contain some payload data. This is the data length */
		size_t dataLength;
		/** most echo requests/replies contain some payload data. This is a pointer to this data */
		uint8_t* data;
	} icmp_echo_request;

	/**
	 * @typedef icmp_echo_reply
	 * ICMP echo (ping) reply message structure, same as icmp_echo_request
	 */
	typedef icmp_echo_request icmp_echo_reply;

	/**
	 * @struct icmp_timestamp_request
	 * ICMP timestamp request message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_timestamp_request : icmphdr
	{
		/** the timestamp request identifier */
		uint16_t id;
		/** the timestamp request sequence number */
		uint16_t sequence;
		/** the time (in milliseconds since midnight) the sender last touched the packet */
		uint32_t originateTimestamp;
		/** relevant for timestamp reply only - the time the echoer first touched it on receipt */
		uint32_t receiveTimestamp;
		/** relevant for timestamp reply only - the time the echoer last touched the message on sending it */
		uint32_t transmitTimestamp;
	} icmp_timestamp_request;
#pragma pack(pop)

	/**
	 * @typedef icmp_timestamp_reply
	 * ICMP timestamp reply message structure, same as icmp_timestamp_request
	 */
	typedef icmp_timestamp_request icmp_timestamp_reply;

	/**
	 * @struct icmp_destination_unreachable
	 * ICMP destination unreachable message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_destination_unreachable : icmphdr
	{
		/** unused 2 bytes */
		uint16_t unused;
		/** contains the MTU of the next-hop network if a code 4 error occurs */
		uint16_t nextHopMTU;
	} icmp_destination_unreachable;
#pragma pack(pop)

	/**
	 * @struct icmp_time_exceeded
	 * ICMP time-to-live exceeded message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_time_exceeded : icmphdr
	{
		/** unused 4 bytes */
		uint32_t unused;
	} icmp_time_exceeded;
#pragma pack(pop)

	/**
	 * @typedef icmp_source_quench
	 * ICMP source quence message structure, same as icmp_time_exceeded
	 */
	typedef icmp_time_exceeded icmp_source_quench;

	/**
	 * @struct icmp_param_problem
	 * ICMP parameter problem message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_param_problem : icmphdr
	{
		/** in the case of an invalid IP header (Code 0), this field indicates the byte offset of the error in the
		 * header */
		uint8_t pointer;
		/** unused 1 byte */
		uint8_t unused1;
		/** unused 2 bytes */
		uint16_t unused2;
	} icmp_param_problem;
#pragma pack(pop)

	/**
	 * @typedef icmp_router_solicitation
	 * ICMP router solicitation message structure, same as icmphdr
	 */
	typedef icmphdr icmp_router_solicitation;

	/**
	 * @struct icmp_redirect
	 * ICMP redirect message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_redirect : icmphdr
	{
		/** an IPv4 address of the gateway to which the redirection should be sent */
		uint32_t gatewayAddress;
	} icmp_redirect;
#pragma pack(pop)

	/**
	 * @struct icmp_router_address_structure
	 * Router address structure, relevant for ICMP router advertisement message type (icmp_router_advertisement)
	 */
#pragma pack(push, 1)
	struct icmp_router_address_structure
	{
		/** the IPv4 address of the advertised router */
		uint32_t routerAddress;
		/** The preferability of the router address as a default router address, relative to other router addresses
		 * on the same subnet. This is a twos-complement value where higher values indicate that the route is
		 * more preferable */
		uint32_t preferenceLevel;

		/**
		 * Set router address structure from a given IPv4 address and preference level
		 * @param[in] addr IPv4 address to set
		 * @param[in] preference Preference level to set
		 */
		void setRouterAddress(IPv4Address addr, uint32_t preference);

		/**
		 * @return The IPv4 address extracted from icmp_router_address_structure#routerAddress field
		 */
		IPv4Address getAddress() const
		{
			return routerAddress;
		}
	};
#pragma pack(pop)

	/**
	 * @struct icmp_router_advertisement_hdr
	 * ICMP router advertisement message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_router_advertisement_hdr : icmphdr
	{
		/** the number of router advertisements in this message. Each advertisement contains one router
		 * address/preference level pair */
		uint8_t advertisementCount;
		/** the number of 32-bit words of information for each router address entry in the list. The value is normally
		 * set to 2 (router address + preference level) */
		uint8_t addressEntrySize;
		/** the maximum number of seconds that the router addresses in this list may be considered valid */
		uint16_t lifetime;
	} icmp_router_advertisement_hdr;
#pragma pack(pop)

	/**
	 * @struct icmp_router_advertisement
	 * ICMP router advertisement message structure
	 */
	struct icmp_router_advertisement
	{
		/** a pointer to the header data on the packet */
		icmp_router_advertisement_hdr* header;

		/**
		 * Extract router advertisement at a given index
		 * @param[in] index The index of the router advertisement
		 * @return A pointer to the router advertisement on the packet or null if index is out of range (less than zero
		 * or greater than the number of router advertisement records on this message, determined by advertisementCount
		 * field)
		 */
		icmp_router_address_structure* getRouterAddress(int index) const;
	};

	/**
	 * @struct icmp_address_mask_request
	 * ICMP address mask request message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_address_mask_request : icmphdr
	{
		/** the address mask request identifier */
		uint16_t id;
		/** the address mask request sequence */
		uint16_t sequence;
		/** the subnet mask of the requesting host */
		uint32_t addressMask;
	} icmp_address_mask_request;
#pragma pack(pop)

	/**
	 * @typedef icmp_address_mask_reply
	 * ICMP address mask reply message structure, same as icmp_address_mask_request
	 */
	typedef icmp_address_mask_request icmp_address_mask_reply;

	/**
	 * @struct icmp_info_request
	 * ICMP information request message structure
	 */
#pragma pack(push, 1)
	typedef struct icmp_info_request : icmphdr
	{
		/** the information request identifier */
		uint16_t id;
		/** the information request sequence */
		uint16_t sequence;
	} icmp_info_request;
#pragma pack(pop)

	/**
	 * @typedef icmp_info_reply
	 * ICMP information reply message structure, same as icmp_info_request
	 */
	typedef icmp_info_request icmp_info_reply;

	/**
	 * @class IcmpLayer
	 * Represents an ICMP protocol layer (for IPv4 only)
	 */
	class IcmpLayer : public Layer
	{
	private:
		icmp_echo_request m_EchoData;
		mutable icmp_router_advertisement m_RouterAdvData;

		bool cleanIcmpLayer();

		bool setEchoData(IcmpMessageType echoType, uint16_t id, uint16_t sequence, uint64_t timestamp,
		                 const uint8_t* data, size_t dataLen);

		bool setIpAndL4Layers(IPv4Layer* ipLayer, Layer* l4Layer);

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		// cppcheck-suppress uninitMemberVar
		IcmpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, ICMP)
		{}

		/**
		 * An empty constructor that creates a new layer with an empty ICMP header without setting the ICMP type or ICMP
		 * data. Call the set*Data() methods to set ICMP type and data
		 */
		IcmpLayer();

		virtual ~IcmpLayer()
		{}

		/**
		 * Get a pointer to the basic ICMP header. Notice this points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the @ref icmphdr
		 */
		icmphdr* getIcmpHeader() const
		{
			return (icmphdr*)m_Data;
		}

		/**
		 * @return The ICMP message type
		 */
		IcmpMessageType getMessageType() const;

		/**
		 * @param[in] type Type to check
		 * @return True if the layer if of the given type, false otherwise
		 */
		bool isMessageOfType(IcmpMessageType type) const
		{
			return getMessageType() == type;
		}

		/**
		 * @return ICMP echo (ping) request data. If the layer isn't of type ICMP echo request nullptr is returned
		 */
		icmp_echo_request* getEchoRequestData();

		/**
		 * Set echo (ping) request message data
		 * @param[in] id Echo (ping) request identifier
		 * @param[in] sequence Echo (ping) request sequence
		 * @param[in] timestamp Echo (ping) request timestamp
		 * @param[in] data A pointer to echo (ping) request payload to set
		 * @param[in] dataLen The length of the echo (ping) request payload
		 * @return A pointer to the echo (ping) request data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_echo_request* setEchoRequestData(uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data,
		                                      size_t dataLen);

		/**
		 * @return ICMP echo reply data. If the layer isn't of type ICMP echo reply nullptr is returned
		 */
		icmp_echo_reply* getEchoReplyData();

		/**
		 * Set echo (ping) reply message data
		 * @param[in] id Echo (ping) reply identifier
		 * @param[in] sequence Echo (ping) reply sequence
		 * @param[in] timestamp Echo (ping) reply timestamp
		 * @param[in] data A pointer to echo (ping) reply payload to set
		 * @param[in] dataLen The length of the echo (ping) reply payload
		 * @return A pointer to the echo (ping) reply data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_echo_reply* setEchoReplyData(uint16_t id, uint16_t sequence, uint64_t timestamp, const uint8_t* data,
		                                  size_t dataLen);

		/**
		 * @return ICMP timestamp request data. If the layer isn't of type ICMP timestamp request nullptr is returned
		 */
		icmp_timestamp_request* getTimestampRequestData();

		/**
		 * Set timestamp request message data
		 * @param[in] id Timestamp request identifier
		 * @param[in] sequence Timestamp request sequence
		 * @param[in] originateTimestamp Time (in milliseconds since midnight) the sender last touched the packet
		 * @return A pointer to the timestamp request data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_timestamp_request* setTimestampRequestData(uint16_t id, uint16_t sequence, timeval originateTimestamp);

		/**
		 * @return ICMP timestamp reply data. If the layer isn't of type ICMP timestamp reply nullptr is returned
		 */
		icmp_timestamp_reply* getTimestampReplyData();

		/**
		 * Set timestamp reply message data
		 * @param[in] id Timestamp reply identifier
		 * @param[in] sequence Timestamp reply sequence
		 * @param[in] originateTimestamp Time (in milliseconds since midnight) the sender last touched the packet
		 * @param[in] receiveTimestamp The time the echoer first touched it on receipt
		 * @param[in] transmitTimestamp The time the echoer last touched the message on sending it
		 * @return A pointer to the timestamp reply data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_timestamp_reply* setTimestampReplyData(uint16_t id, uint16_t sequence, timeval originateTimestamp,
		                                            timeval receiveTimestamp, timeval transmitTimestamp);

		/**
		 * @return ICMP destination unreachable data. If the layer isn't of type ICMP destination unreachable nullptr is
		 * returned. The IP and L4 (ICMP/TCP/UDP) headers of the destination unreachable data are parsed as separate
		 * layers and can be retrieved via this->getNextLayer()
		 */
		icmp_destination_unreachable* getDestUnreachableData();

		/**
		 * Set destination unreachable message data. This method only works if IcmpLayer is already part of a packet
		 * (not a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate
		 * layers and need a packet to be added to
		 * @param[in] code Destination unreachable code
		 * @param[in] nextHopMTU The MTU of the next-hop network if a code 4 error occurs
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the
		 * packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the destination unreachable data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_destination_unreachable* setDestUnreachableData(IcmpDestUnreachableCodes code, uint16_t nextHopMTU,
		                                                     IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP source quench data. If the layer isn't of type ICMP source quench nullptr is returned.
		 * The IP and L4 (ICMP/TCP/UDP) headers of the source quench data are parsed as separate layers and can be
		 * retrieved via this->getNextLayer()
		 */
		icmp_source_quench* getSourceQuenchdata();

		/**
		 * Set source quench message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate
		 * layers and need a packet to be added to
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the
		 * packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the source quench data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_source_quench* setSourceQuenchdata(IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP redirect data. If the layer isn't of type ICMP redirect nullptr is returned.
		 * The IP and L4 (ICMP/TCP/UDP) headers of the redirect data are parsed as separate layers and can be
		 * retrieved via this->getNextLayer()
		 */
		icmp_redirect* getRedirectData();

		/**
		 * Set redirect message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate
		 * layers and need a packet to be added to
		 * @param[in] code The redirect message code. Only values between 0 and 3 are legal, the rest will cause the
		 * method to fail
		 * @param[in] gatewayAddress An IPv4 address of the gateway to which the redirection should be sent
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the
		 * packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the redirect data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_redirect* setRedirectData(uint8_t code, IPv4Address gatewayAddress, IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP router advertisement data. If the layer isn't of type ICMP router advertisement nullptr is
		 * returned
		 */
		icmp_router_advertisement* getRouterAdvertisementData() const;

		/**
		 * Set router advertisement message data
		 * @param[in] code The router advertisement message code. Only codes 0 or 16 are legal, the rest will fail the
		 * method
		 * @param[in] lifetimeInSeconds The maximum number of seconds that the router addresses in this list may be
		 * considered valid
		 * @param[in] routerAddresses A vector of router advertisements to set
		 * @return A pointer to the router advertisement data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_router_advertisement* setRouterAdvertisementData(
		    uint8_t code, uint16_t lifetimeInSeconds,
		    const std::vector<icmp_router_address_structure>& routerAddresses);

		/**
		 * @return ICMP router solicitation data. If the layer isn't of type ICMP router solicitation nullptr is
		 * returned
		 */
		icmp_router_solicitation* getRouterSolicitationData();

		/**
		 * Set router solicitation message data. This message accepts no parameters as there are no parameters to this
		 * type of message (code is always zero)
		 * @return A pointer to the router solicitation data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_router_solicitation* setRouterSolicitationData();

		/**
		 * @return ICMP time-to-live exceeded data. If the layer isn't of type ICMP time-to-live exceeded nullptr is
		 * returned. The IP and L4 (ICMP/TCP/UDP) headers of the time exceeded data are parsed as separate layers and
		 * can be retrieved via this->getNextLayer()
		 */
		icmp_time_exceeded* getTimeExceededData();

		/**
		 * Set time-to-live exceeded message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate
		 * layers and need a packet to be added to
		 * @param[in] code Time-to-live exceeded message code. Only codes 0 or 1 are legal, the rest will fail the
		 * method
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the
		 * packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the time-to-live exceeded data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_time_exceeded* setTimeExceededData(uint8_t code, IPv4Layer* ipHeader, Layer* l4Header);

		/**
		 * @return ICMP parameter problem data. If the layer isn't of type ICMP parameter problem nullptr is returned
		 */
		icmp_param_problem* getParamProblemData();

		/**
		 * Set parameter problem message data. This method only works if IcmpLayer is already part of a packet (not
		 * a standalone layer). The reason is the Internet and L4 headers given as parameters are added as separate
		 * layers and need a packet to be added to
		 * @param[in] code Parameter problem message code. Only code between 0 and 2 are legal, the rest will fail the
		 * method
		 * @param[in] errorOctetPointer In the case of an invalid IP header (Code 0), indicate the byte offset of the
		 * error in the header
		 * @param[in] ipHeader The Internet header of the original data. This layer is added as a separate layer on the
		 * packet
		 * @param[in] l4Header The L4 header of the original data. This layer is added as a separate layer on the packet
		 * @return A pointer to the parameter problem data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_param_problem* setParamProblemData(uint8_t code, uint8_t errorOctetPointer, IPv4Layer* ipHeader,
		                                        Layer* l4Header);

		/**
		 * @return ICMP address mask request data. If the layer isn't of type ICMP address mask request nullptr is
		 * returned
		 */
		icmp_address_mask_request* getAddressMaskRequestData();

		/**
		 * Set address mask request message data
		 * @param[in] id Address mask request identifier
		 * @param[in] sequence Address mask request sequence
		 * @param[in] mask The subnet mask of the requesting host
		 * @return A pointer to the address mask request data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_address_mask_request* setAddressMaskRequestData(uint16_t id, uint16_t sequence, IPv4Address mask);

		/**
		 * @return ICMP address mask reply data. If the layer isn't of type ICMP address mask reply nullptr is returned
		 */
		icmp_address_mask_reply* getAddressMaskReplyData();

		/**
		 * Set address mask reply message data
		 * @param[in] id Address mask reply identifier
		 * @param[in] sequence Address mask reply sequence
		 * @param[in] mask The subnet mask of the requesting host
		 * @return A pointer to the address mask reply data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_address_mask_reply* setAddressMaskReplyData(uint16_t id, uint16_t sequence, IPv4Address mask);

		/**
		 * @return ICMP address information request data. If the layer isn't of type ICMP information request nullptr is
		 * returned
		 */
		icmp_info_request* getInfoRequestData();

		/**
		 * Set information request message data
		 * @param[in] id Information request identifier
		 * @param[in] sequence Information request sequence
		 * @return A pointer to the information request data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_info_request* setInfoRequestData(uint16_t id, uint16_t sequence);

		/**
		 * @return ICMP address information reply data. If the layer isn't of type ICMP information reply nullptr is
		 * returned
		 */
		icmp_info_reply* getInfoReplyData();

		/**
		 * Set information reply message data
		 * @param[in] id Information reply identifier
		 * @param[in] sequence Information reply sequence
		 * @return A pointer to the information reply data that have been set or nullptr if something went wrong
		 * (an appropriate error log is printed in such cases)
		 */
		icmp_info_reply* setInfoReplyData(uint16_t id, uint16_t sequence);

		/**
		 * The static method makes validation of input data
		 * @param[in] data The pointer to the beginning of byte stream of ICMP packet
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent an ICMP packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * ICMP messages of types: ICMP_DEST_UNREACHABLE, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED, ICMP_REDIRECT,
		 * ICMP_PARAM_PROBLEM have data that contains IPv4 header and some L4 header (TCP/UDP/ICMP). This method parses
		 * these headers as separate layers on top of the ICMP layer
		 */
		void parseNextLayer();

		/**
		 * @return The ICMP header length. This length varies according to the ICMP message type. This length doesn't
		 * include IPv4 and L4 headers in case ICMP message type are: ICMP_DEST_UNREACHABLE, ICMP_SOURCE_QUENCH,
		 * ICMP_TIME_EXCEEDED, ICMP_REDIRECT, ICMP_PARAM_PROBLEM
		 */
		size_t getHeaderLen() const;

		/**
		 * Calculate ICMP checksum field
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}
	};

	// implementation of inline methods

	bool IcmpLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < sizeof(icmphdr))
			return false;

		uint8_t type = data[0];

		// ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY, ICMP_ROUTER_SOL, ICMP_INFO_REQUEST, ICMP_INFO_REPLY
		if (type == 8 || type == 0 || type == 10 || type == 15 || type == 16)
			return true;

		// ICMP_TIMESTAMP_REQUEST, ICMP_TIMESTAMP_REPLY
		if (type == 13 || type == 14)
			return dataLen >= sizeof(icmp_timestamp_request);

		// ICMP_ADDRESS_MASK_REPLY, ICMP_ADDRESS_MASK_REQUEST
		if (type == 17 || type == 18)
			return dataLen >= sizeof(icmp_address_mask_request);

		// ICMP_DEST_UNREACHABLE
		if (type == 3)
			return dataLen >= sizeof(icmp_destination_unreachable);

		// ICMP_REDIRECT
		if (type == 5)
			return dataLen >= sizeof(icmp_redirect);

		// ICMP_TIME_EXCEEDED, ICMP_SOURCE_QUENCH
		if (type == 4 || type == 11)
			return dataLen >= sizeof(icmp_time_exceeded);

		// ICMP_PARAM_PROBLEM
		if (type == 12)
			return dataLen >= sizeof(icmp_param_problem);

		// ICMP_ROUTER_ADV
		if (type == 9)
			return dataLen >= sizeof(icmp_router_advertisement_hdr);

		return false;
	}

}  // namespace vanhooks::net
// ---- end IcmpLayer.h ----

// ---- begin IcmpV6Layer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * An enum representing the available ICMPv6 message types
	 */
	enum class ICMPv6MessageType : int
	{
		/** Unknown ICMPv6 message */
		ICMPv6_UNKNOWN_MESSAGE = 0,
		/** Destination Unreachable Message */
		ICMPv6_DESTINATION_UNREACHABLE = 1,
		/** Packet Too Big Message */
		ICMPv6_PACKET_TOO_BIG = 2,
		/** Time Exceeded Message */
		ICMPv6_TIME_EXCEEDED = 3,
		/** Parameter Problem Message */
		ICMPv6_PARAMETER_PROBLEM = 4,
		/** Private Experimentation Message */
		ICMPv6_PRIVATE_EXPERIMENTATION1 = 100,
		/** Private Experimentation Message */
		ICMPv6_PRIVATE_EXPERIMENTATION2 = 101,
		/** Reserved for expansion of ICMPv6 error messages */
		ICMPv6_RESERVED_EXPANSION_ERROR = 127,
		/** Echo Request Message */
		ICMPv6_ECHO_REQUEST = 128,
		/** Echo Reply Message */
		ICMPv6_ECHO_REPLY = 129,
		/** Multicast Listener Query Message */
		ICMPv6_MULTICAST_LISTENER_QUERY = 130,
		/** Multicast Listener Report Message */
		ICMPv6_MULTICAST_LISTENER_REPORT = 131,
		/** Multicast Listener Done Message */
		ICMPv6_MULTICAST_LISTENER_DONE = 132,
		/** Router Solicitation Message */
		ICMPv6_ROUTER_SOLICITATION = 133,
		/** Router Advertisement Message */
		ICMPv6_ROUTER_ADVERTISEMENT = 134,
		/** Neighbor Solicitation Message */
		ICMPv6_NEIGHBOR_SOLICITATION = 135,
		/** Neighbor Advertisement Message */
		ICMPv6_NEIGHBOR_ADVERTISEMENT = 136,
		/** Redirect Message */
		ICMPv6_REDIRECT_MESSAGE = 137,
		/** Router Renumbering Message */
		ICMPv6_ROUTER_RENUMBERING = 138,
		/** Node Information Query Message */
		ICMPv6_ICMP_NODE_INFORMATION_QUERY = 139,
		/** Node Information Reply Message*/
		ICMPv6_ICMP_NODE_INFORMATION_RESPONSE = 140,
		/** Inverse Neighbor Discovery Solicitation Message */
		ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_SOLICITATION_MESSAGE = 141,
		/** Inverse Neighbor Discovery Advertisement Message */
		ICMPv6_INVERSE_NEIGHBOR_DISCOVERY_ADVERTISEMENT_MESSAGE = 142,
		/** Multicast Listener Report Message */
		ICMPv6_MULTICAST_LISTENER_DISCOVERY_REPORTS = 143,
		/** Home Agent Address Discovery Request Message */
		ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REQUEST_MESSAGE = 144,
		/** Home Agent Address Discovery Reply Message */
		ICMPv6_HOME_AGENT_ADDRESS_DISCOVERY_REPLY_MESSAGE = 145,
		/** Mobile Prefix Solicitation Message */
		ICMPv6_MOBILE_PREFIX_SOLICITATION = 146,
		/** Mobile Prefix Advertisement Message */
		ICMPv6_MOBILE_PREFIX_ADVERTISEMENT = 147,
		/** Certification Path Solicitation Message */
		ICMPv6_CERTIFICATION_PATH_SOLICITATION = 148,
		/** Certification Path Advertisement Message */
		ICMPv6_CERTIFICATION_PATH_ADVERTISEMENT = 149,
		/** ICMP Experimental Mobility Subtype Format and Registry Message */
		ICMPv6_EXPERIMENTAL_MOBILITY = 150,
		/** Multicast Router Advertisement Message */
		ICMPv6_MULTICAST_ROUTER_ADVERTISEMENT = 151,
		/** Multicast Router Solicitation Message */
		ICMPv6_MULTICAST_ROUTER_SOLICITATION = 152,
		/** Multicast Router Termination Message*/
		ICMPv6_MULTICAST_ROUTER_TERMINATION = 153,
		/** RPL Control Message */
		ICMPv6_RPL_CONTROL_MESSAGE = 155,
		/** Private Experimentation Message */
		ICMPv6_PRIVATE_EXPERIMENTATION3 = 200,
		/** Private Experimentation Message */
		ICMPv6_PRIVATE_EXPERIMENTATION4 = 201,
		/** Reserved for expansion of ICMPv6 informational messages */
		ICMPv6_RESERVED_EXPANSION_INFORMATIONAL = 255
	};

/**
 * @struct icmpv6hdr
 * Represents an ICMPv6 protocol header
 */
#pragma pack(push, 1)
	struct icmpv6hdr
	{
		/** Type of the message. Values in the range from 0 to 127 (high-order bit is 0) indicate an error message,
		while values in the range from 128 to 255 (high-order bit is 1) indicate an information message. */
		uint8_t type;
		/** The code field value depends on the message type and provides an additional level of message granularity */
		uint8_t code;
		/** The checksum field provides a minimal level of integrity verification for the ICMP message */
		uint16_t checksum;
	};
#pragma pack(pop)

/**
 * @struct icmpv6_echo_hdr
 * ICMP echo request/reply message structure
 */
#pragma pack(push, 1)
	typedef struct icmpv6_echo_hdr : icmpv6hdr
	{
		/** the echo request identifier */
		uint16_t id;
		/** the echo request sequence number */
		uint16_t sequence;
	} icmpv6_echo_hdr;
#pragma pack(pop)

	/**
	 * @class IcmpV6Layer
	 * Base class for ICMPv6 protocol layers which provides common logic for ICMPv6 messages.
	 */
	class IcmpV6Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param data A pointer to the raw data
		 * @param dataLen Size of the data in bytes
		 * @param prevLayer A pointer to the previous layer
		 * @param packet A pointer to the Packet instance where layer will be stored in
		 */
		IcmpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, ICMPv6)
		{}

		/**
		 * A constructor that allocates a new ICMPv6 layer with type, code and data
		 * @param[in] msgType Message type of the ICMPv6 layer
		 * @param[in] code Code field of the ICMPv6 layer
		 * @param[in] data A pointer to the payload to set
		 * @param[in] dataLen The length of the payload
		 */
		IcmpV6Layer(ICMPv6MessageType msgType, uint8_t code, const uint8_t* data, size_t dataLen);

		virtual ~IcmpV6Layer()
		{}

		/**
		 * A static method that creates an ICMPv6 layer from packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return Layer* A newly allocated ICMPv6 layer
		 */
		static Layer* parseIcmpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * @param[in] type Type to check
		 * @return True if the layer if of the given type, false otherwise
		 */
		bool isMessageOfType(ICMPv6MessageType type) const
		{
			return getMessageType() == type;
		}

		/**
		 * @return Get the ICMPv6 Message Type
		 */
		ICMPv6MessageType getMessageType() const;

		/**
		 * @return Get the code header field
		 */
		uint8_t getCode() const;

		/**
		 * @return Get the checksum header field in host representation
		 */
		uint16_t getChecksum() const;

		/**
		 * Does nothing for this layer. ICMPv6 is the last layer.
		 */
		void parseNextLayer()
		{}

		/**
		 * @return The size of the ICMPv6 message
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		/**
		 * Calculate ICMPv6 checksum field
		 */
		void computeCalculateFields();

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}

		std::string toString() const;

	protected:
		IcmpV6Layer() = default;

	private:
		void calculateChecksum();
		icmpv6hdr* getIcmpv6Header() const
		{
			return (icmpv6hdr*)m_Data;
		}
	};

	/**
	 * @class ICMPv6EchoLayer
	 * Represents an ICMPv6 echo request/reply protocol layer
	 */
	class ICMPv6EchoLayer : public IcmpV6Layer
	{
	public:
		/**
		 * An enum representing ICMPv6 echo message types
		 */
		enum ICMPv6EchoType
		{
			/** Echo Request Type */
			REQUEST,
			/** Echo Reply Type */
			REPLY
		};

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ICMPv6EchoLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : IcmpV6Layer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor for a new echo request/reply layer
		 * @param[in] echoType The type of the echo message
		 * @param[in] id Echo request identifier
		 * @param[in] sequence Echo request sequence number
		 * @param[in] data A pointer to echo request payload to set
		 * @param[in] dataLen The length of the echo request payload
		 */
		ICMPv6EchoLayer(ICMPv6EchoType echoType, uint16_t id, uint16_t sequence, const uint8_t* data, size_t dataLen);

		virtual ~ICMPv6EchoLayer()
		{}

		/**
		 * @return Identifier in host representation
		 */
		uint16_t getIdentifier() const;

		/**
		 * @return Sequence number in host representation
		 */
		uint16_t getSequenceNr() const;

		/**
		 * @return Size of the data in bytes
		 */
		size_t getEchoDataLen() const
		{
			return m_DataLen - sizeof(icmpv6_echo_hdr);
		}

		/**
		 * @return Pointer to the beginning of the data
		 */
		uint8_t* getEchoDataPtr() const
		{
			return m_Data + sizeof(icmpv6_echo_hdr);
		}

		std::string toString() const;

	private:
		icmpv6_echo_hdr* getEchoHeader() const
		{
			return (icmpv6_echo_hdr*)m_Data;
		}
	};

}  // namespace vanhooks::net
// ---- end IcmpV6Layer.h ----

// ---- begin IgmpLayer.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct igmp_header
	 * IGMPv1 and IGMPv2 basic protocol header
	 */
	struct igmp_header
	{
		/** Indicates the message type. The enum for message type is vanhooks::net::IgmpType */
		uint8_t type;
		/** Specifies the time limit for the corresponding report. The field has a resolution of 100 milliseconds */
		uint8_t maxResponseTime;
		/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
		uint16_t checksum;
		/** This is the multicast address being queried when sending a Group-Specific or Group-and-Source-Specific Query
		 */
		uint32_t groupAddress;
	};

	/**
	 * @struct igmpv3_query_header
	 * IGMPv3 membership query basic header
	 */
	struct igmpv3_query_header
	{
		/** IGMP message type. Should always have value of membership query (::IgmpType_MembershipQuery)  */
		uint8_t type;
		/** This field specifies the maximum time (in 1/10 second) allowed before sending a responding report */
		uint8_t maxResponseTime;
		/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
		uint16_t checksum;
		/** This is the multicast address being queried when sending a Group-Specific or Group-and-Source-Specific Query
		 */
		uint32_t groupAddress;
		/** Suppress Router-side Processing Flag + Querier's Robustness Variable */
		uint8_t s_qrv;
		/** Querier's Query Interval Code */
		uint8_t qqic;
		/** This field specifies the number of source addresses present in the Query */
		uint16_t numOfSources;
	};

	/**
	 * @struct igmpv3_report_header
	 * IGMPv3 membership report basic header
	 */
	struct igmpv3_report_header
	{
		/** IGMP message type. Should always have value of IGMPv3 membership report (::IgmpType_MembershipReportV3)  */
		uint8_t type;
		/** Unused byte */
		uint8_t reserved1;
		/** This is the 16-bit one's complement of the one's complement sum of the entire IGMP message */
		uint16_t checksum;
		/** Unused bytes */
		uint16_t reserved2;
		/** This field specifies the number of group records present in the Report */
		uint16_t numOfGroupRecords;
	};

	/**
	 * @struct igmpv3_group_record
	 * A block of fields containing information pertaining to the sender's membership in a single multicast group on the
	 * interface from which the Report is sent. Relevant only for IGMPv3 membership report messages
	 */
	struct igmpv3_group_record
	{
		/** Group record type */
		uint8_t recordType;
		/** Contains the length of the Auxiliary Data field in this Group Record. A value other than 0 isn't supported
		 */
		uint8_t auxDataLen;
		/** Specifies how many source addresses are present in this Group Record */
		uint16_t numOfSources;
		/** Contains the IP multicast address to which this Group Record pertains */
		uint32_t multicastAddress;
		/** A vector of n IP unicast addresses, where n is the value in this record's Number of Sources field */
		uint8_t sourceAddresses[];

		/**
		 * @return The multicast address in igmpv3_group_record#multicastAddress as IPv4Address instance
		 */
		IPv4Address getMulticastAddress() const
		{
			return multicastAddress;
		}

		/**
		 * @return The number of source addresses in this group record
		 */
		uint16_t getSourceAddressCount() const;

		/**
		 * Get the source address at a certain index
		 * @param[in] index The index of the source address in the group record
		 * @return The source address in the requested index. If index is negative or higher than the number of source
		 * addresses in this group record the value if IPv4Address#Zero is returned
		 */
		IPv4Address getSourceAddressAtIndex(int index) const;

		/**
		 * @return The total size in bytes of the group record
		 */
		size_t getRecordLen() const;
	};

	/**
	 * IGMP message types
	 */
	enum IgmpType
	{
		/** Unknown message type */
		IgmpType_Unknown = 0,
		/** IGMP Membership Query */
		IgmpType_MembershipQuery = 0x11,
		/** IGMPv1 Membership Report */
		IgmpType_MembershipReportV1 = 0x12,
		/** DVMRP */
		IgmpType_DVMRP = 0x13,
		/** PIM version 1 */
		IgmpType_P1Mv1 = 0x14,
		/** Cisco Trace Messages */
		IgmpType_CiscoTrace = 0x15,
		/** IGMPv2 Membership Report */
		IgmpType_MembershipReportV2 = 0x16,
		/** IGMPv2 Leave Group */
		IgmpType_LeaveGroup = 0x17,
		/** Multicast Traceroute Response */
		IgmpType_MulticastTracerouteResponse = 0x1e,
		/** Multicast Traceroute */
		IgmpType_MulticastTraceroute = 0x1f,
		/** IGMPv3 Membership Report */
		IgmpType_MembershipReportV3 = 0x22,
		/** MRD, Multicast Router Advertisement */
		IgmpType_MulticastRouterAdvertisement = 0x30,
		/** MRD, Multicast Router Solicitation */
		IgmpType_MulticastRouterSolicitation = 0x31,
		/** MRD, Multicast Router Termination */
		IgmpType_MulticastRouterTermination = 0x32,
	};

	/**
	 * @class IgmpLayer
	 * A base class for all IGMP (Internet Group Management Protocol) protocol classes. This is an abstract class and
	 * cannot be instantiated, only its child classes can be instantiated. The inherited classes represent the different
	 * versions of the protocol: IGMPv1, IGMPv2 and IGMPv3
	 */
	class IgmpLayer : public Layer
	{
	protected:
		IgmpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType igmpVer)
		    : Layer(data, dataLen, prevLayer, packet, igmpVer)
		{}

		IgmpLayer(IgmpType type, const IPv4Address& groupAddr, uint8_t maxResponseTime, ProtocolType igmpVer);

		uint16_t calculateChecksum();

		size_t getHeaderSizeByVerAndType(ProtocolType igmpVer, IgmpType igmpType) const;

	public:
		virtual ~IgmpLayer()
		{}

		/**
		 * Get a pointer to the raw IGMPv1/IGMPv2 header. Notice this points directly to the data, so every change will
		 * change the actual packet data
		 * @return A pointer to the @ref igmp_header
		 */
		igmp_header* getIgmpHeader() const
		{
			return (igmp_header*)m_Data;
		}

		/**
		 * @return The IPv4 multicast address stored igmp_header#groupAddress
		 */
		IPv4Address getGroupAddress() const
		{
			return getIgmpHeader()->groupAddress;
		}

		/**
		 * Set the IPv4 multicast address
		 * @param[in] groupAddr The IPv4 address to set
		 */
		void setGroupAddress(const IPv4Address& groupAddr);

		/**
		 * @return IGMP type set in igmp_header#type as ::IgmpType enum. Notice that if igmp_header#type contains a
		 * value that doesn't appear in the ::IgmpType enum, ::IgmpType_Unknown will be returned
		 */
		IgmpType getType() const;

		/**
		 * Set IGMP type (will be written to igmp_header#type field)
		 * @param[in] type The type to set
		 */
		void setType(IgmpType type);

		/**
		 * A static method that gets raw IGMP data (byte stream) and returns the IGMP version of this IGMP message
		 * @param[in] data The IGMP raw data (byte stream)
		 * @param[in] dataLen Raw data length
		 * @param[out] isQuery Return true if IGMP message type is ::IgmpType_MembershipQuery and false otherwise
		 * @return One of the values ::IGMPv1, ::IGMPv2, ::IGMPv3 according to detected IGMP version or
		 * ::UnknownProtocol if couldn't detect IGMP version
		 */
		static ProtocolType getIGMPVerFromData(uint8_t* data, size_t dataLen, bool& isQuery);

		// implement abstract methods

		/**
		 * Does nothing for this layer (IGMP layer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return Size of IGMP header = 8B
		 */
		size_t getHeaderLen() const
		{
			return sizeof(igmp_header);
		}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}
	};

	/**
	 * @class IgmpV1Layer
	 * Represents IGMPv1 (Internet Group Management Protocol ver 1) layer. This class represents all the different
	 * messages of IGMPv1
	 */
	class IgmpV1Layer : public IgmpLayer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IgmpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : IgmpLayer(data, dataLen, prevLayer, packet, IGMPv1)
		{}

		/**
		 * A constructor that allocates a new IGMPv1 header
		 * @param[in] type The message type to set
		 * @param[in] groupAddr The multicast address to set. This is an optional parameter and has a default value of
		 * IPv4Address#Zero if not provided
		 */
		explicit IgmpV1Layer(IgmpType type, const IPv4Address& groupAddr = IPv4Address())
		    : IgmpLayer(type, groupAddr, 0, IGMPv1)
		{}

		/**
		 * A destructor for this layer (does nothing)
		 */
		~IgmpV1Layer()
		{}

		// implement abstract methods

		/**
		 * Calculate the IGMP checksum and set igmp_header#maxResponseTime to 0 (this field is unused in IGMPv1)
		 */
		void computeCalculateFields();
	};

	/**
	 * @class IgmpV2Layer
	 * Represents IGMPv2 (Internet Group Management Protocol ver 2) layer. This class represents all the different
	 * messages of IGMPv2
	 */
	class IgmpV2Layer : public IgmpLayer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IgmpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : IgmpLayer(data, dataLen, prevLayer, packet, IGMPv2)
		{}

		/**
		 * A constructor that allocates a new IGMPv2 header
		 * @param[in] type The message type to set
		 * @param[in] groupAddr The multicast address to set. This is an optional parameter and has a default value of
		 * unspecified/zero IPv4 address
		 * @param[in] maxResponseTime The max response time to set. This is an optional parameter and has a default
		 * value of 0 if not provided
		 */
		explicit IgmpV2Layer(IgmpType type, const IPv4Address& groupAddr = IPv4Address(), uint8_t maxResponseTime = 0)
		    : IgmpLayer(type, groupAddr, maxResponseTime, IGMPv2)
		{}

		/**
		 * A destructor for this layer (does nothing)
		 */
		~IgmpV2Layer()
		{}

		// implement abstract methods

		/**
		 * Calculate the IGMP checksum
		 */
		void computeCalculateFields();
	};

	/**
	 * @class IgmpV3QueryLayer
	 * Represents an IGMPv3 (Internet Group Management Protocol ver 3) membership query message
	 */
	class IgmpV3QueryLayer : public IgmpLayer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IgmpV3QueryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new IGMPv3 membership query
		 * @param[in] multicastAddr The multicast address to set. This is an optional parameter and has a default value
		 * of unspecified/zero IPv4 address if not provided
		 * @param[in] maxResponseTime The max response time to set. This is an optional parameter and has a default
		 * value of 0 if not provided
		 * @param[in] s_qrv A 1-byte value representing the value in Suppress Router-side Processing Flag + Querier's
		 * Robustness Variable (igmpv3_query_header#s_qrv field). This is an optional parameter and has a default value
		 * of 0 if not provided
		 */
		explicit IgmpV3QueryLayer(const IPv4Address& multicastAddr = IPv4Address(), uint8_t maxResponseTime = 0,
		                          uint8_t s_qrv = 0);

		/**
		 * Get a pointer to the raw IGMPv3 membership query header. Notice this points directly to the data, so every
		 * change will change the actual packet data
		 * @return A pointer to the @ref igmpv3_query_header
		 */
		igmpv3_query_header* getIgmpV3QueryHeader() const
		{
			return (igmpv3_query_header*)m_Data;
		}

		/**
		 * @return The number of source addresses in this message (as extracted from the
		 * igmpv3_query_header#numOfSources field)
		 */
		uint16_t getSourceAddressCount() const;

		/**
		 * Get the IPV4 source address in a certain index
		 * @param[in] index The requested index of the source address
		 * @return The IPv4 source address, or IPv4Address#Zero if index is out of bounds (of the message or of the
		 * layer)
		 */
		IPv4Address getSourceAddressAtIndex(int index) const;

		/**
		 * Add a new source address at the end of the source address list. The igmpv3_query_header#numOfSources field
		 * will be incremented accordingly
		 * @param[in] addr The IPv4 source address to add
		 * @return True if source address was added successfully or false otherwise. If false is returned an appropriate
		 * error message will be printed to log
		 */
		bool addSourceAddress(const IPv4Address& addr);

		/**
		 * Add a new source address at a certain index of the source address list. The igmpv3_query_header#numOfSources
		 * field will be incremented accordingly
		 * @param[in] addr The IPv4 source address to add
		 * @param[in] index The index to add the new source address at
		 * @return True if source address was added successfully or false otherwise. If false is returned an appropriate
		 * error message will be printed to log
		 */
		bool addSourceAddressAtIndex(const IPv4Address& addr, int index);

		/**
		 * Remove a source address at a certain index. The igmpv3_query_header#numOfSources field will be decremented
		 * accordingly
		 * @param[in] index The index of the source address to be removed
		 * @return True if source address was removed successfully or false otherwise. If false is returned an
		 * appropriate error message will be printed to log
		 */
		bool removeSourceAddressAtIndex(int index);

		/**
		 * Remove all source addresses in the message. The igmpv3_query_header#numOfSources field will be set to 0
		 * @return True if all source addresses were cleared successfully or false otherwise. If false is returned an
		 * appropriate error message will be printed to log
		 */
		bool removeAllSourceAddresses();

		// implement abstract methods

		/**
		 * Calculate the IGMP checksum
		 */
		void computeCalculateFields();

		/**
		 * @return The message size in bytes which include the size of the basic header + the size of the source address
		 * list
		 */
		size_t getHeaderLen() const;
	};

	/**
	 * @class IgmpV3ReportLayer
	 * Represents an IGMPv3 (Internet Group Management Protocol ver 3) membership report message
	 */
	class IgmpV3ReportLayer : public IgmpLayer
	{
	private:
		igmpv3_group_record* addGroupRecordAt(uint8_t recordType, const IPv4Address& multicastAddress,
		                                      const std::vector<IPv4Address>& sourceAddresses, int offset);

	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		IgmpV3ReportLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : IgmpLayer(data, dataLen, prevLayer, packet, IGMPv3)
		{}

		/**
		 * A constructor that allocates a new IGMPv3 membership report with 0 group addresses
		 */
		IgmpV3ReportLayer() : IgmpLayer(IgmpType_MembershipReportV3, IPv4Address(), 0, IGMPv3)
		{}

		/**
		 * Get a pointer to the raw IGMPv3 membership report header. Notice this points directly to the data, so every
		 * change will change the actual packet data
		 * @return A pointer to the @ref igmpv3_report_header
		 */
		igmpv3_report_header* getReportHeader() const
		{
			return (igmpv3_report_header*)m_Data;
		}

		/**
		 * @return The number of group records in this message (as extracted from the
		 * igmpv3_report_header#numOfGroupRecords field)
		 */
		uint16_t getGroupRecordCount() const;

		/**
		 * @return A pointer to the first group record or nullptr if no group records exist. Notice the return value is
		 * a pointer to the real data, so changes in the return value will affect the packet data
		 */
		igmpv3_group_record* getFirstGroupRecord() const;

		/**
		 * Get the group record that comes next to a given group record. If "groupRecord" is nullptr then nullptr will
		 * be returned. If "groupRecord" is the last group record or if it is out of layer bounds nullptr will be
		 * returned also. Notice the return value is a pointer to the real data casted to igmpv3_group_record type (as
		 * opposed to a copy of the option data). So changes in the return value will affect the packet data
		 * @param[in] groupRecord The group record to start searching from
		 * @return The next group record or nullptr if "groupRecord" is nullptr, last or out of layer bounds
		 */
		igmpv3_group_record* getNextGroupRecord(igmpv3_group_record* groupRecord) const;

		/**
		 * Add a new group record at a the end of the group record list. The igmpv3_report_header#numOfGroupRecords
		 * field will be incremented accordingly
		 * @param[in] recordType The type of the new group record
		 * @param[in] multicastAddress The multicast address of the new group record
		 * @param[in] sourceAddresses A vector containing all the source addresses of the new group record
		 * @return The method constructs a new group record, adds it to the end of the group record list of IGMPv3
		 * report message and returns a pointer to the new message. If something went wrong in creating or adding the
		 * new group record a nullptr value is returned and an appropriate error message is printed to log
		 */
		igmpv3_group_record* addGroupRecord(uint8_t recordType, const IPv4Address& multicastAddress,
		                                    const std::vector<IPv4Address>& sourceAddresses);

		/**
		 * Add a new group record at a certain index of the group record list. The
		 * igmpv3_report_header#numOfGroupRecords field will be incremented accordingly
		 * @param[in] recordType The type of the new group record
		 * @param[in] multicastAddress The multicast address of the new group record
		 * @param[in] sourceAddresses A vector containing all the source addresses of the new group record
		 * @param[in] index The index to add the new group address at
		 * @return The method constructs a new group record, adds it to the IGMPv3 report message and returns a pointer
		 * to the new message. If something went wrong in creating or adding the new group record a nullptr value is
		 * returned and an appropriate error message is printed to log
		 */
		igmpv3_group_record* addGroupRecordAtIndex(uint8_t recordType, const IPv4Address& multicastAddress,
		                                           const std::vector<IPv4Address>& sourceAddresses, int index);

		/**
		 * Remove a group record at a certain index. The igmpv3_report_header#numOfGroupRecords field will be
		 * decremented accordingly
		 * @param[in] index The index of the group record to be removed
		 * @return True if group record was removed successfully or false otherwise. If false is returned an appropriate
		 * error message will be printed to log
		 */
		bool removeGroupRecordAtIndex(int index);

		/**
		 * Remove all group records in the message. The igmpv3_report_header#numOfGroupRecords field will be set to 0
		 * @return True if all group records were cleared successfully or false otherwise. If false is returned an
		 * appropriate error message will be printed to log
		 */
		bool removeAllGroupRecords();

		// implement abstract methods

		/**
		 * Calculate the IGMP checksum
		 */
		void computeCalculateFields();

		/**
		 * @return The message size in bytes which include the size of the basic header + the size of the group record
		 * list
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}
	};

}  // namespace vanhooks::net
// ---- end IgmpLayer.h ----

// ---- begin GreLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct gre_basic_header
	 * Represents GRE basic protocol header (common for GREv0 and GREv1)
	 */
#pragma pack(push, 1)
	struct gre_basic_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Number of additional encapsulations which are permitted. 0 is the default value */
		uint8_t recursionControl : 3,
		    /** Strict source routing bit (GRE v0 only) */
		    strictSourceRouteBit : 1,
		    /** Set if sequence number exists */
		    sequenceNumBit : 1,
		    /** Set if key exists */
		    keyBit : 1,
		    /** Set if routing exists (GRE v0 only) */
		    routingBit : 1,
		    /** Set if checksum exists (GRE v0 only) */
		    checksumBit : 1;
#else
		/** Set if checksum exists (GRE v0 only) */
		uint8_t checksumBit : 1,
		    /** Set if routing exists (GRE v0 only) */
		    routingBit : 1,
		    /** Set if key exists */
		    keyBit : 1,
		    /** Set if sequence number exists */
		    sequenceNumBit : 1,
		    /** Strict source routing bit (GRE v0 only) */
		    strictSourceRouteBit : 1,
		    /** Number of additional encapsulations which are permitted. 0 is the default value */
		    recursionControl : 3;
#endif
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** GRE version - can be 0 or 1 */
		uint8_t version : 3,
		    /** Reserved */
		    flags : 4,
		    /** Set if acknowledgment number is set (GRE v1 only) */
		    ackSequenceNumBit : 1;
#else
		/** Set if acknowledgment number is set (GRE v1 only) */
		uint8_t ackSequenceNumBit : 1,
		    /** Reserved */
		    flags : 4,
		    /** GRE version - can be 0 or 1 */
		    version : 3;
#endif

		/** Protocol type of the next layer */
		uint16_t protocol;
	};
#pragma pack(pop)

	/**
	 * @struct gre1_header
	 * Represents GREv1 protocol header
	 */
#pragma pack(push, 1)
	struct gre1_header : gre_basic_header
	{
		/** Size of the payload not including the GRE header */
		uint16_t payloadLength;
		/** Contains the Peer's Call ID for the session to which this packet belongs */
		uint16_t callID;
	};
#pragma pack(pop)

	/**
	 * @struct ppp_pptp_header
	 * Represents PPP layer that comes after GREv1 as part of PPTP protocol
	 */
#pragma pack(push, 1)
	struct ppp_pptp_header
	{
		/** Broadcast address */
		uint8_t address;
		/** Control byte */
		uint8_t control;
		/** Protocol type of the next layer (see PPP_* macros at PPPoELayer.h) */
		uint16_t protocol;
	};
#pragma pack(pop)

	/**
	 * @class GreLayer
	 * Abstract base class for GRE layers (GREv0Layer and GREv1Layer). Cannot be instantiated and contains common logic
	 * for derived classes
	 */
	class GreLayer : public Layer
	{
	public:
		virtual ~GreLayer()
		{}

		/**
		 * A static method that determines the GRE version of GRE layer raw data by looking at the
		 * gre_basic_header#version field
		 * @param[in] greData GRE layer raw data
		 * @param[in] greDataLen Size of raw data
		 * @return ::GREv0 or ::GREv1 values if raw data is GREv0 or GREv1 (accordingly) or ::UnknownProtocol otherwise
		 */
		static ProtocolType getGREVersion(uint8_t* greData, size_t greDataLen);

		/**
		 * Get sequence number value if field exists in layer
		 * @param[out] seqNumber The returned sequence number value if exists in layer. Else remain unchanged
		 * @return True if sequence number field exists in layer. In this case seqNumber will be filled with the value.
		 * Or false if sequence number field doesn't exist in layer
		 */
		bool getSequenceNumber(uint32_t& seqNumber) const;

		/**
		 * Set sequence number value. If field already exists (gre_basic_header#sequenceNumBit is set) then only the new
		 * value is set. If field doesn't exist it will be added to the layer, gre_basic_header#sequenceNumBit will be
		 * set and the new value will be set
		 * @param[in] seqNumber The sequence number value to set
		 * @return True if managed to set the value successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setSequenceNumber(uint32_t seqNumber);

		/**
		 * Unset sequence number and remove it from the layer
		 * @return True if managed to unset successfully or false (and error log) if sequence number wasn't set in the
		 * first place or if didn't manage to remove it from the layer
		 */
		bool unsetSequenceNumber();

		// implement abstract methods

		/**
		 * Currently identifies the following next layers:
		 *   IPv4Layer, IPv6Layer, VlanLayer, MplsLayer, PPP_PPTPLayer, EthLayer, EthDot3Layer
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of GRE header (may change if optional fields are added or removed)
		 */
		size_t getHeaderLen() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}

	protected:
		GreLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol)
		    : Layer(data, dataLen, prevLayer, packet, protocol)
		{}

		GreLayer()
		{}

		enum GreField
		{
			GreChecksumOrRouting = 0,
			GreKey = 1,
			GreSeq = 2,
			GreAck = 3
		};

		uint8_t* getFieldValue(GreField field, bool returnOffsetEvenIfFieldMissing) const;

		void computeCalculateFieldsInner();
	};

	/**
	 * @class GREv0Layer
	 * Represents a GRE version 0 protocol. Limitation: currently this layer doesn't support GRE routing information
	 * parsing and editing. So if a GREv0 packet includes routing information it won't be parse correctly. I didn't add
	 * it because of lack of time, but if you need it please tell me and I'll add it
	 */
	class GREv0Layer : public GreLayer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GREv0Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GreLayer(data, dataLen, prevLayer, packet, GREv0)
		{}

		/**
		 * A constructor that creates a new GREv0 header and allocates the data
		 */
		GREv0Layer();

		virtual ~GREv0Layer()
		{}

		/**
		 * Get a pointer to the basic GRE header containing only non-optional fields. Notice this points directly to the
		 * data, so every change will change the actual packet data. Also please notice that changing the set bits
		 * (gre_basic_header#strictSourceRouteBit, gre_basic_header#sequenceNumBit, gre_basic_header#keyBit,
		 * gre_basic_header#routingBit, gre_basic_header#checksumBit, gre_basic_header#ackSequenceNumBit) without using
		 * the proper set or unset methods (such as setChecksum(), unsetChecksum(), etc.) may result to wrong
		 * calculation of header length and really weird bugs. Please avoid doing so
		 * @return A pointer to the gre_basic_header
		 */
		gre_basic_header* getGreHeader() const
		{
			return (gre_basic_header*)m_Data;
		}

		/**
		 * Get checksum value if field exists in layer
		 * @param[out] checksum The returned checksum value if exists in layer. Else remain unchanged
		 * @return True if checksum field exists in layer. In this case checksum parameter will be filled with the
		 * value. Or false if checksum field doesn't exist in layer
		 */
		bool getChecksum(uint16_t& checksum);

		/**
		 * Set checksum value. If checksum or offset fields already exist (gre_basic_header#checksumBit or
		 * gre_basic_header#routingBit are set) then only the new value is set. If both fields don't exist a new 4-byte
		 * value will be added to the layer, gre_basic_header#checksumBit will be set (gre_basic_header#routingBit will
		 * remain unset), the new checksum value will be set and offset value will be set to 0. The reason both fields
		 * are added is that GREv0 protocol states both of them or none of them should exist on packet (even if only one
		 * of the bits are set)
		 * @param[in] checksum The checksum value to set
		 * @return True if managed to set the value/s successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setChecksum(uint16_t checksum);

		/**
		 * Unset checksum and possibly remove it from the layer. It will be removed from the layer only if
		 * gre_basic_header#routingBit is not set as well. Otherwise checksum field will remain on packet with value of
		 * 0
		 * @return True if managed to unset successfully or false (and error log) if checksum wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetChecksum();

		/**
		 * Get offset value if field exists in layer. Notice there is no setOffset() method as GRE routing information
		 * isn't supported yet (see comment on class description)
		 * @param[out] offset The returned offset value if exists in layer. Else remain unchanged
		 * @return True if offset field exists in layer. In this case offset parameter will be filled with the value.
		 * Or false if offset field doesn't exist in layer
		 */
		bool getOffset(uint16_t& offset) const;

		/**
		 * Get key value if field exists in layer
		 * @param[out] key The returned key value if exists in layer. Else remain unchanged
		 * @return True if key field exists in layer. In this case key parameter will be filled with the value.
		 * Or false if key field doesn't exist in layer
		 */
		bool getKey(uint32_t& key) const;

		/**
		 * Set key value. If field already exists (gre_basic_header#keyBit is set) then only the new value is set.
		 * If field doesn't exist it will be added to the layer, gre_basic_header#keyBit will be set
		 * and the new value will be set
		 * @param[in] key The key value to set
		 * @return True if managed to set the value successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setKey(uint32_t key);

		/**
		 * Unset key and remove it from the layer
		 * @return True if managed to unset successfully or false (and error log) if key wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetKey();

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an GREv0 layer
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an GREv0 layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(gre_basic_header);
		}

		// implement abstract methods

		/**
		 * Calculate the following fields:
		 * - gre_basic_header#protocol
		 * - GRE checksum field (if exists in packet)
		 */
		void computeCalculateFields();

		std::string toString() const;
	};

	/**
	 * @class GREv1Layer
	 * Represents a GRE version 1 protocol
	 */
	class GREv1Layer : public GreLayer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GREv1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : GreLayer(data, dataLen, prevLayer, packet, GREv1)
		{}

		/**
		 * A constructor that creates a new GREv1 header and allocates the data
		 * @param[in] callID The call ID to set
		 */
		explicit GREv1Layer(uint16_t callID);

		virtual ~GREv1Layer()
		{}

		/**
		 * Get a pointer to the basic GREv1 header containing all non-optional fields. Notice this points directly to
		 * the data, so every change will change the actual packet data. Also please notice that changing the set bits
		 * (gre_basic_header#strictSourceRouteBit, gre_basic_header#sequenceNumBit, gre_basic_header#keyBit,
		 * gre_basic_header#routingBit, gre_basic_header#checksumBit, gre_basic_header#ackSequenceNumBit) without using
		 * the proper set or unset methods (such as setAcknowledgmentNum(), unsetSequenceNumber(), etc.) may result to
		 * wrong calculation of header length or illegal GREv1 packet and to some really weird bugs. Please avoid doing
		 * so
		 * @return A pointer to the gre1_header
		 */
		gre1_header* getGreHeader() const
		{
			return (gre1_header*)m_Data;
		}

		/**
		 * Get acknowledgment (ack) number value if field exists in layer
		 * @param[out] ackNum The returned ack number value if exists in layer. Else remain unchanged
		 * @return True if ack number field exists in layer. In this case ackNum will be filled with the value.
		 * Or false if ack number field doesn't exist in layer
		 */
		bool getAcknowledgmentNum(uint32_t& ackNum) const;

		/**
		 * Set acknowledgment (ack) number value. If field already exists (gre_basic_header#ackSequenceNumBit is set)
		 * then only the new value is set. If field doesn't exist it will be added to the layer,
		 * gre_basic_header#ackSequenceNumBit will be set and the new value will be set
		 * @param[in] ackNum The ack number value to set
		 * @return True if managed to set the value successfully, or false otherwise (if couldn't extend the layer)
		 */
		bool setAcknowledgmentNum(uint32_t ackNum);

		/**
		 * Unset acknowledgment (ack) number and remove it from the layer
		 * @return True if managed to unset successfully or false (and error log) if ack number wasn't set in the first
		 * place or if didn't manage to remove it from the layer
		 */
		bool unsetAcknowledgmentNum();

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an GREv1 layer
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an GREv1 layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(gre1_header);
		}

		// implement abstract methods

		/**
		 * Calculate the following fields:
		 * - gre1_header#payloadLength
		 * - gre_basic_header#protocol
		 */
		void computeCalculateFields();

		std::string toString() const;
	};

	/**
	 * @class PPP_PPTPLayer
	 * Represent a PPP (point-to-point) protocol header that comes after GREv1 header, as part of PPTP - Point-to-Point
	 * Tunneling Protocol
	 */
	class PPP_PPTPLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref ppp_pptp_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		PPP_PPTPLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, PPP_PPTP)
		{}

		/**
		 * A constructor that allocates a new PPP-PPTP header
		 * @param[in] address Address field
		 * @param[in] control Control field
		 */
		PPP_PPTPLayer(uint8_t address, uint8_t control);

		~PPP_PPTPLayer()
		{}

		/**
		 * Get a pointer to the PPP-PPTP header. Notice this points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the @ref ppp_pptp_header
		 */
		ppp_pptp_header* getPPP_PPTPHeader() const
		{
			return (ppp_pptp_header*)m_Data;
		}

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return The size of @ref ppp_pptp_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(ppp_pptp_header);
		}

		/**
		 * Calculate the following fields:
		 * - ppp_pptp_header#protocol
		 */
		void computeCalculateFields();

		std::string toString() const
		{
			return "PPP for PPTP Layer";
		}

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelSesionLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end GreLayer.h ----

// ---- begin IPSecLayer.h ----
/// @file


/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @struct ipsec_authentication_header
	 * Represents IPSec AuthenticationHeader (AH) structure
	 */
#pragma pack(push, 1)
	struct ipsec_authentication_header
	{
		/** Type of the next header */
		uint8_t nextHeader;
		/** The length of the Authentication Header in 4-octet units, minus 2 */
		uint8_t payloadLen;
		/** Reserved */
		uint16_t reserved;
		/** Security Parameters Index */
		uint32_t spi;
		/** Sequence Number */
		uint32_t sequenceNumber;
	};
#pragma pack(pop)

	/**
	 * @struct ipsec_esp
	 * Represents IPSec Encapsulating Security Payload (ESP) structure
	 */
#pragma pack(push, 1)
	struct ipsec_esp
	{
		/** Security Parameters Index */
		uint32_t spi;
		/** Sequence Number */
		uint32_t sequenceNumber;
	};
#pragma pack(pop)

	/**
	 * @class AuthenticationHeaderLayer
	 * Represents an IPSec AuthenticationHeader (AH) layer
	 */
	class AuthenticationHeaderLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		AuthenticationHeaderLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, AuthenticationHeader)
		{}

		/**
		 * Get a pointer to the raw AH header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the ipsec_authentication_header
		 */
		ipsec_authentication_header* getAHHeader() const
		{
			return (ipsec_authentication_header*)m_Data;
		}

		/**
		 * @return The Security Parameters Index (SPI) field value
		 */
		uint32_t getSPI() const;

		/**
		 * @return The sequence number value
		 */
		uint32_t getSequenceNumber() const;

		/**
		 * @return The size of the Integrity Check Value (ICV)
		 */
		size_t getICVLength() const;

		/**
		 * @return A pointer to the raw data of the Integrity Check Value (ICV)
		 */
		uint8_t* getICVBytes() const;

		/**
		 * @return The value of the Integrity Check Value (ICV) as a hex string
		 */
		std::string getICVHexStream() const;

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of a AuthenticationHeader layer
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent an AuthenticationHeader layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * @return The size of the AH header
		 */
		size_t getHeaderLen() const
		{
			return 4 * (getAHHeader()->payloadLen + 2);
		}

		/**
		 * Currently identifies the following next layers: UdpLayer, TcpLayer, IPv4Layer, IPv6Layer and ESPLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields()
		{}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}

	private:
		// this layer supports parsing only
		AuthenticationHeaderLayer()
		{}
	};

	/**
	 * @class ESPLayer
	 * Represents an IPSec Encapsulating Security Payload (ESP) layer
	 */
	class ESPLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ESPLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, ESP)
		{}

		ipsec_esp* getESPHeader() const
		{
			return reinterpret_cast<ipsec_esp*>(m_Data);
		}

		/**
		 * @return The Security Parameters Index (SPI) field value
		 */
		uint32_t getSPI() const;

		/**
		 * @return The sequence number value
		 */
		uint32_t getSequenceNumber() const;

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of a ESP layer
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent an ESP layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * @return The size of the ESP header (8 bytes)
		 */
		size_t getHeaderLen() const
		{
			return sizeof(ipsec_esp);
		}

		/**
		 * The payload of an ESP layer is encrypted, hence the next layer is always a generic payload (PayloadLayer)
		 */
		void parseNextLayer();

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields()
		{}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelTransportLayer;
		}

	private:
		// this layer supports parsing only
		ESPLayer()
		{}
	};

	// implementation of inline methods

	bool AuthenticationHeaderLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < sizeof(ipsec_authentication_header))
			return false;

		size_t payloadLen = 4 * (data[1] + 2);
		if (payloadLen < sizeof(ipsec_authentication_header) || payloadLen > dataLen)
			return false;

		return true;
	}

	bool ESPLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(ipsec_esp);
	}
}  // namespace vanhooks::net
// ---- end IPSecLayer.h ----

// ---- begin VxlanLayer.h ----
/// @file

namespace vanhooks::net
{

	/**
	 * @struct vxlan_header
	 * Represents a VXLAN protocol header
	 */
#pragma pack(push, 1)
	struct vxlan_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Reserved bits */
		uint16_t reserved6_8 : 3;
		/** VNI present flag */
		uint16_t vniPresentFlag : 1;
		/** Reserved bits */
		uint16_t reserved2_4 : 3;
		/** GBP flag */
		uint16_t gbpFlag : 1;
		/** Reserved bits */
		uint16_t reserved14_16 : 3;
		/** Policy applied flag */
		uint16_t policyAppliedFlag : 1;
		/** Reserved bits */
		uint16_t reserved11_12 : 2;
		/** Don't learn flag */
		uint16_t dontLearnFlag : 1;
		/** Reserved bits */
		uint16_t reserved9 : 1;
#else
		/** Reserved bits */
		uint16_t reserved9 : 1;
		/** Don't learn flag */
		uint16_t dontLearnFlag : 1;
		/** Reserved bits */
		uint16_t reserved11_12 : 2;
		/** Policy applied flag */
		uint16_t policyAppliedFlag : 1;
		/** Reserved bits */
		uint16_t reserved14_16 : 3;
		/** GBP flag */
		uint16_t gbpFlag : 1;
		/** Reserved bits */
		uint16_t reserved2_4 : 3;
		/** VNI present flag */
		uint16_t vniPresentFlag : 1;
		/** Reserved bits */
		uint16_t reserved6_8 : 3;
#endif

		/** Group Policy ID */
		uint16_t groupPolicyID;

		/** VXLAN Network ID (VNI) */
		uint32_t vni : 24;
		/** Reserved bits */
		uint32_t pad : 8;
	};
#pragma pack(pop)

	/**
	 * @class VxlanLayer
	 * Represents a VXLAN (Virtual eXtensible Local Area Network) protocol layer
	 */
	class VxlanLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		VxlanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, VXLAN)
		{}

		/**
		 * A constructor that creates a new VXLAN header and allocates the data. Note: the VNI present flag is set
		 * automatically
		 * @param[in] vni VNI (VXLAN Network ID) to set. Optional parameter (default is 0)
		 * @param[in] groupPolicyID Group Policy ID to set. Optional parameter (default is 0)
		 * @param[in] setGbpFlag Set GBP flag. Optional parameter (default is false)
		 * @param[in] setPolicyAppliedFlag Set Policy Applied flag. Optional parameter (default is false)
		 * @param[in] setDontLearnFlag Set Don't Learn flag. Optional parameter (default is false)
		 */
		explicit VxlanLayer(uint32_t vni = 0, uint16_t groupPolicyID = 0, bool setGbpFlag = false,
		                    bool setPolicyAppliedFlag = false, bool setDontLearnFlag = false);

		~VxlanLayer()
		{}

		/**
		 * Get a pointer to the VXLAN header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the vxlan_header
		 */
		vxlan_header* getVxlanHeader() const
		{
			return (vxlan_header*)m_Data;
		}

		/**
		 * @return The VXLAN Network ID (VNI) value
		 */
		uint32_t getVNI() const;

		/**
		 * Set VXLAN Network ID (VNI) value
		 * @param[in] vni VNI value to set
		 */
		void setVNI(uint32_t vni);

		/**
		 * A static method that checks whether the port is considered as VxLAN
		 * @param[in] port The port number to be checked
		 */
		static bool isVxlanPort(uint16_t port)
		{
			return port == 4789;
		}

		// implement abstract methods

		/**
		 * Next layer for VXLAN is always Ethernet
		 */
		void parseNextLayer();

		/**
		 * @return Size of vxlan_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(vxlan_header);
		}

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields()
		{}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end VxlanLayer.h ----

// ---- begin VrrpLayer.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	For more info see:
	    https://datatracker.ietf.org/doc/html/rfc2338
	    https://datatracker.ietf.org/doc/html/rfc3768
	    https://datatracker.ietf.org/doc/html/rfc5798
	*/

	/* VRRPv2 Packet Format
	    0                   1                   2                   3
	    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |Version| Type  | Virtual Rtr ID|   Priority    | Count IP Addrs|
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |   Auth Type   |   Adver Int   |          Checksum             |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         IP Address (1)                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                            .                                  |
	   |                            .                                  |
	   |                            .                                  |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                         IP Address (n)                        |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                     Authentication Data (1)                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	   |                     Authentication Data (2)                   |
	   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	/* VRRPv3 Packet Format
	     0                   1                   2                   3
	     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |                    IPv4 Fields or IPv6 Fields                 |
	   ...                                                             ...
	    |                                                               |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |(rsvd) |     Max Adver Int     |          Checksum             |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	    |                                                               |
	    +                                                               +
	    |                       IPvX Address(es)                        |
	    +                                                               +
	    +                                                               +
	    +                                                               +
	    +                                                               +
	    |                                                               |
	    +                                                               +
	    |                                                               |
	    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	/**
	 * @struct vrrp_header
	 * VRRP generic header
	 */
	struct vrrp_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** Type */
		uint8_t type : 4;

		/** Version bits */
		uint8_t version : 4;
#else
		/** Version bits */
		uint8_t version : 4;

		/** Type */
		uint8_t type : 4;
#endif
		/** The Virtual Router Identifier (VRID) field identifies the virtual router this packet is reporting status
		 * for*/
		uint8_t vrId;

		/** This specifies the sending VRRP router's priority for the virtual router */
		uint8_t priority;

		/** Specifies how many IPvX addresses are present in this Packet */
		uint8_t ipAddrCount;

		/** This specifies authentication type(v2) or (Max) Advertisement interval (in seconds(v2) or
		 * centi-seconds(v3)). */
		uint16_t authTypeAdvInt;

		/** This specifies checksum field that is used to detect data corruption in the VRRP message.
		 * VRRPv2 uses normal checksum algorithm, while VRRPv3 uses "pseudo-header" checksum algorithm. */
		uint16_t checksum;

		/** This specifies one or more IPvX addresses that are associated with the virtual router. */
		uint8_t* ipAddresses[];
	};

	/**
	 * @class VrrpLayer
	 * A base class for all VRRP (Virtual Router Redundancy Protocol) protocol classes. This is an abstract class and
	 * cannot be instantiated, only its child classes can be instantiated. The inherited classes represent the different
	 * versions of the protocol: VRRPv2 and VRRPv3
	 */
	class VrrpLayer : public Layer
	{
	private:
		bool addIPAddressesAt(const std::vector<IPAddress>& ipAddresses, int offset);

		uint8_t getIPAddressLen() const;

		bool isIPAddressValid(IPAddress& ipAddress) const;

		uint8_t* getFirstIPAddressPtr() const;

		uint8_t* getNextIPAddressPtr(uint8_t* ipAddressPtr) const;

		IPAddress getIPAddressFromData(uint8_t* data) const;

		void copyIPAddressToData(uint8_t* data, const IPAddress& ipAddress) const;

		IPAddress::AddressType m_AddressType;

	protected:
		VrrpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType vrrpVer,
		          IPAddress::AddressType addressType)
		    : Layer(data, dataLen, prevLayer, packet, vrrpVer), m_AddressType(addressType)
		{}

		explicit VrrpLayer(ProtocolType subProtocol, uint8_t virtualRouterId, uint8_t priority);

		vrrp_header* getVrrpHeader() const
		{
			return (vrrp_header*)m_Data;
		}

		void setAddressType(IPAddress::AddressType addressType);

	public:
		/**
		 * VRRP message types
		 */
		enum VrrpType
		{
			/** Unknown VRRP message */
			VrrpType_Unknown = 0,

			/** VRRP advertisement message */
			VrrpType_Advertisement = 1
		};

		/**
		 * An enum describing VRRP special priority values
		 */
		enum VrrpPriority
		{
			/** Default priority for a backup VRRP router (value of 100) */
			Default,
			/** Current Master has stopped participating in VRRP (value of 0) */
			Stop,
			/** This VRRP router owns the virtual router's IP address(es) (value of 255) */
			Owner,
			/** Other priority */
			Other
		};

		virtual ~VrrpLayer()
		{}

		/**
		 * @return The VRRP IP Address type
		 */
		IPAddress::AddressType getAddressType() const;

		/**
		 * A static method that validates the input data
		 * @param[in] data VRRP raw data (byte stream)
		 * @param[in] dataLen The length of the byte stream
		 * @return One of the values ::VRRPv2, ::VRRPv3 according to detected VRRP version or ::UnknownProtocol if
		 * couldn't detect VRRP version
		 */
		static ProtocolType getVersionFromData(uint8_t* data, size_t dataLen);

		/**
		 * @return VRRP version of this message
		 */
		uint8_t getVersion() const;

		/**
		 * @return VRRP type set in vrrp_header#type as VrrpLayer::VrrpType enum.
		 */
		VrrpType getType() const;

		/**
		 * @return The virtual router id (vrId) in this message
		 */
		uint8_t getVirtualRouterID() const;

		/**
		 * Set the virtual router ID
		 * @param virtualRouterID new ID to set
		 */
		void setVirtualRouterID(uint8_t virtualRouterID);

		/**
		 * @return The priority in this message
		 */
		uint8_t getPriority() const;

		/**
		 * @return An enum describing VRRP priority
		 */
		VrrpPriority getPriorityAsEnum() const;

		/**
		 * Set the priority
		 * @param priority new priority to set
		 */
		void setPriority(uint8_t priority);

		/**
		 * @return VRRP checksum of this message
		 */
		uint16_t getChecksum() const;

		/**
		 * Fill the checksum from header and data and write the result to @ref vrrp_header#checksum
		 */
		void calculateAndSetChecksum();

		/**
		 * Calculate the checksum from header and data and write the result to @ref vrrp_header#checksum
		 * @return The checksum result
		 */
		virtual uint16_t calculateChecksum() const = 0;

		/**
		 * @return True if VRRP checksum is correct
		 */
		bool isChecksumCorrect() const;

		/**
		 * @return The count of VRRP virtual IP addresses in this message
		 */
		uint8_t getIPAddressesCount() const;

		/**
		 * @return A list of the virtual IP addresses in this message
		 */
		std::vector<IPAddress> getIPAddresses() const;

		/**
		 * Add a list of virtual IP addresses at a the end of the virtual IP address list. The
		 * vrrp_header#ipAddressCount field will be incremented accordingly
		 * @param[in] ipAddresses A vector containing all the virtual IP address
		 * @return true if added successfully, false otherwise
		 */
		bool addIPAddresses(const std::vector<IPAddress>& ipAddresses);

		/**
		 * Add a virtual IP address at a the end of the virtual IP address list. The vrrp_header#ipAddressCount field
		 * will be incremented accordingly
		 * @param[in] ipAddress Virtual IP address to add
		 * @return true if add successfully, false otherwise
		 */
		bool addIPAddress(const IPAddress& ipAddress);

		/**
		 * Remove a virtual IP address at a certain index. The vrrp_header#ipAddressCount field will be decremented
		 * accordingly
		 * @param[in] index The index of the virtual IP address to be removed
		 * @return True if virtual IP address was removed successfully or false otherwise. If false is returned an
		 * appropriate error message will be printed to log
		 */
		bool removeIPAddressAtIndex(int index);

		/**
		 * Remove all virtual IP addresses in the message. The vrrp_header#ipAddressCount field will be set to 0
		 * @return True if virtual IP addresses were cleared successfully or false otherwise. If false is returned an
		 * appropriate error message will be printed to log
		 */
		bool removeAllIPAddresses();

		// implement abstract methods

		/**
		 * Does nothing for this layer (VRRP layer is always last)
		 */
		void parseNextLayer() override
		{}

		/**
		 * Calculate the VRRP checksum
		 */
		void computeCalculateFields() override;

		/**
		 * @return The message size in bytes which include the size of the basic header + the size of the IP address(es)
		 */
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelNetworkLayer;
		}
	};

	/**
	 * @class VrrpV2Layer
	 * Represents VRRPv2 (Virtual Router Redundancy Protocol ver 2) layer. This class represents all the different
	 * messages of VRRPv2
	 */
	class VrrpV2Layer : public VrrpLayer
	{
	private:
		struct vrrpv2_auth_adv
		{
			uint8_t authType;
			uint8_t advInt;
		};

	public:
		/**
		 * VRRP v2 authentication types
		 */
		enum class VrrpAuthType : uint8_t
		{
			/** No Authentication */
			NoAuthentication = 0,
			/** Simple Text Password */
			SimpleTextPassword = 1,
			/** IP Authentication Header */
			IPAuthenticationHeader = 2,
			/** Cisco VRRP MD5 Authentication */
			MD5 = 3,
			/** Other/Unknown Authentication Type */
			Other = 4
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		VrrpV2Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : VrrpLayer(data, dataLen, prevLayer, packet, VRRPv2, IPAddress::IPv4AddressType)
		{}

		/**
		 * A constructor that allocates a new VRRP v2 layer
		 * @param virtualRouterId Virtual router ID
		 * @param priority Priority
		 * @param advInt Advertisement interval
		 * @param authType Authentication type (default value is 0)
		 */
		explicit VrrpV2Layer(uint8_t virtualRouterId, uint8_t priority, uint8_t advInt, uint8_t authType = 0);

		/**
		 * A destructor for this layer (does nothing)
		 */
		~VrrpV2Layer()
		{}

		/**
		 * @return The VRRP advertisement interval in this message
		 */
		uint8_t getAdvInt() const;

		/**
		 * Set advertisement interval value in this message
		 * @param advInt value to set
		 */
		void setAdvInt(uint8_t advInt);

		/**
		 * @return The authentication type in this message
		 */
		uint8_t getAuthType() const;

		/**
		 * @return The VRRP authentication type as enum
		 */
		VrrpAuthType getAuthTypeAsEnum() const;

		/**
		 * Set VRRP authentication type
		 * @param authType value to set
		 */
		void setAuthType(uint8_t authType);

		// implement abstract methods

		/**
		 * Calculate the checksum from header and data and write the result to @ref vrrp_header#checksum
		 * @return The checksum result
		 */
		uint16_t calculateChecksum() const override;
	};

	/**
	 * @class VrrpV3Layer
	 * Represents VRRPv3 (Virtual Router Redundancy Protocol ver 3) layer. This class represents all the different
	 * messages of VRRP
	 */
	class VrrpV3Layer : public VrrpLayer
	{
	private:
		struct vrrpv3_rsvd_adv
		{
			uint16_t maxAdvInt;
		};

	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @param[in] addressType The IP address type to set for this layer
		 */
		VrrpV3Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, IPAddress::AddressType addressType)
		    : VrrpLayer(data, dataLen, prevLayer, packet, VRRPv3, addressType)
		{}

		/**
		 * A constructor that allocates a new VRRPv3
		 * @param addressType The IP address type to set for this layer
		 * @param virtualRouterId Virtual router ID
		 * @param priority Priority
		 * @param maxAdvInt Max advertisement interval
		 */
		explicit VrrpV3Layer(IPAddress::AddressType addressType, uint8_t virtualRouterId, uint8_t priority,
		                     uint16_t maxAdvInt);

		/**
		 * A destructor for this layer (does nothing)
		 */
		~VrrpV3Layer()
		{}

		/**
		 * @return The maximum advertisement interval in this message
		 */
		uint16_t getMaxAdvInt() const;

		/**
		 * Set the maximum advertisement interval value
		 * @param maxAdvInt Value to set
		 */
		void setMaxAdvInt(uint16_t maxAdvInt);

		// implement abstract methods

		/**
		 * Calculate the checksum from header and data and write the result to @ref vrrp_header#checksum
		 * @return The checksum result
		 */
		uint16_t calculateChecksum() const override;
	};
}  // namespace vanhooks::net
// ---- end VrrpLayer.h ----

// ---- begin GtpLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

#pragma pack(push, 1)
	/**
	 * @struct gtpv1_header
	 * GTP v1 common message header
	 */
	struct gtpv1_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** A 1-bit value that states whether there is a N-PDU number optional field */
		uint8_t npduNumberFlag : 1,
		    /** A 1-bit value that states whether there is a Sequence Number optional field */
		    sequenceNumberFlag : 1,
		    /** A 1-bit value that states whether there is an extension header optional field */
		    extensionHeaderFlag : 1,
		    /** Reserved bit */
		    reserved : 1,
		    /** A 1-bit value that differentiates GTP (value 1) from GTP' (value 0) */
		    protocolType : 1,
		    /** GTP version */
		    version : 3;
#else
		/** GTP version */
		uint8_t version : 3,
		    /** A 1-bit value that differentiates GTP (value 1) from GTP' (value 0) */
		    protocolType : 1,
		    /** Reserved bit */
		    reserved : 1,
		    /** A 1-bit value that states whether there is an extension header optional field */
		    extensionHeaderFlag : 1,
		    /** A 1-bit value that states whether there is a Sequence Number optional field */
		    sequenceNumberFlag : 1,
		    /** A 1-bit value that states whether there is a N-PDU number optional field */
		    npduNumberFlag : 1;
#endif
		/** An 8-bit field that indicates the type of GTP message */
		uint8_t messageType;

		/** A 16-bit field that indicates the length of the payload in bytes (rest of the packet following the mandatory
		 * 8-byte GTP header). Includes the optional fields */
		uint16_t messageLength;

		/** Tunnel endpoint identifier - A 32-bit(4-octet) field used to multiplex different connections in the same GTP
		 * tunnel */
		uint32_t teid;
	};

#pragma pack(pop)

	/**
	 * An enum representing the possible GTP v1 message types.
	 * All of the message types except for #GtpV1_GPDU are considered GTP-C messages. #GtpV1_GPDU is considered a GTP-U
	 * message
	 */
	enum GtpV1MessageType
	{
		/** GTPv1 Message Type Unknown */
		GtpV1_MessageTypeUnknown = 0,
		/** Echo Request */
		GtpV1_EchoRequest = 1,
		/** Echo Response */
		GtpV1_EchoResponse = 2,
		/** Version Not Supported */
		GtpV1_VersionNotSupported = 3,
		/** Node Alive Request */
		GtpV1_NodeAliveRequest = 4,
		/** Node Alive Response */
		GtpV1_NodeAliveResponse = 5,
		/** Redirection Request */
		GtpV1_RedirectionRequest = 6,
		/** Create PDP Context Request */
		GtpV1_CreatePDPContextRequest = 7,
		/** Create PDP Context Response */
		GtpV1_CreatePDPContextResponse = 16,
		/** Update PDP Context Request */
		GtpV1_UpdatePDPContextRequest = 17,
		/** Update PDP Context Response */
		GtpV1_UpdatePDPContextResponse = 18,
		/** Delete PDP Context Request */
		GtpV1_DeletePDPContextRequest = 19,
		/** Delete PDP Context Response */
		GtpV1_DeletePDPContextResponse = 20,
		/** Initiate PDP Context Activation Request */
		GtpV1_InitiatePDPContextActivationRequest = 22,
		/** Initiate PDP Context Activation Response */
		GtpV1_InitiatePDPContextActivationResponse = 23,
		/** Error Indication */
		GtpV1_ErrorIndication = 26,
		/** PDU Notification Request */
		GtpV1_PDUNotificationRequest = 27,
		/** PDU Notification Response */
		GtpV1_PDUNotificationResponse = 28,
		/** PDU Notification Reject Request */
		GtpV1_PDUNotificationRejectRequest = 29,
		/** PDU Notification Reject Response */
		GtpV1_PDUNotificationRejectResponse = 30,
		/** Supported Extensions Header Notification */
		GtpV1_SupportedExtensionsHeaderNotification = 31,
		/** Send Routing for GPRS Request */
		GtpV1_SendRoutingforGPRSRequest = 32,
		/** Send Routing for GPRS Response */
		GtpV1_SendRoutingforGPRSResponse = 33,
		/** Failure Report Request */
		GtpV1_FailureReportRequest = 34,
		/** Failure Report Response */
		GtpV1_FailureReportResponse = 35,
		/** Note MS Present Request */
		GtpV1_NoteMSPresentRequest = 36,
		/** Note MS Present Response */
		GtpV1_NoteMSPresentResponse = 37,
		/** Identification Request */
		GtpV1_IdentificationRequest = 38,
		/** Identification Response */
		GtpV1_IdentificationResponse = 39,
		/** SGSN Context Request */
		GtpV1_SGSNContextRequest = 50,
		/** SGSN Context Response */
		GtpV1_SGSNContextResponse = 51,
		/** SGSN Context Acknowledge */
		GtpV1_SGSNContextAcknowledge = 52,
		/** Forward Relocation Request */
		GtpV1_ForwardRelocationRequest = 53,
		/** Forward Relocation Response */
		GtpV1_ForwardRelocationResponse = 54,
		/** Forward Relocation Complete */
		GtpV1_ForwardRelocationComplete = 55,
		/** Relocation Cancel Request */
		GtpV1_RelocationCancelRequest = 56,
		/** Relocation Cancel Response */
		GtpV1_RelocationCancelResponse = 57,
		/** Forward SRNS Context */
		GtpV1_ForwardSRNSContext = 58,
		/** Forward Relocation Complete Acknowledge */
		GtpV1_ForwardRelocationCompleteAcknowledge = 59,
		/** Forward SRNS Context Acknowledge */
		GtpV1_ForwardSRNSContextAcknowledge = 60,
		/** UE Registration Request */
		GtpV1_UERegistrationRequest = 61,
		/** UE Registration Response */
		GtpV1_UERegistrationResponse = 62,
		/** RAN Information Relay */
		GtpV1_RANInformationRelay = 70,
		/** MBMS Notification Request */
		GtpV1_MBMSNotificationRequest = 96,
		/** MBMS Notification Response */
		GtpV1_MBMSNotificationResponse = 97,
		/** MBMS Notification Reject Request */
		GtpV1_MBMSNotificationRejectRequest = 98,
		/** MBMS Notification Reject Response */
		GtpV1_MBMSNotificationRejectResponse = 99,
		/** Create MBMS Notification Request */
		GtpV1_CreateMBMSNotificationRequest = 100,
		/** Create MBMS Notification Response */
		GtpV1_CreateMBMSNotificationResponse = 101,
		/** Update MBMS Notification Request */
		GtpV1_UpdateMBMSNotificationRequest = 102,
		/** Update MBMS Notification Response */
		GtpV1_UpdateMBMSNotificationResponse = 103,
		/** Delete MBMS Notification Request */
		GtpV1_DeleteMBMSNotificationRequest = 104,
		/** Delete MBMS Notification Response */
		GtpV1_DeleteMBMSNotificationResponse = 105,
		/** MBMS Registration Request */
		GtpV1_MBMSRegistrationRequest = 112,
		/** MBMS Registration Response */
		GtpV1_MBMSRegistrationResponse = 113,
		/** MBMS De-Registration Request */
		GtpV1_MBMSDeRegistrationRequest = 114,
		/** MBMS De-Registration Response */
		GtpV1_MBMSDeRegistrationResponse = 115,
		/** MBMS Session Start Request */
		GtpV1_MBMSSessionStartRequest = 116,
		/** MBMS Session Start Response */
		GtpV1_MBMSSessionStartResponse = 117,
		/** MBMS Session Stop Request */
		GtpV1_MBMSSessionStopRequest = 118,
		/** MBMS Session Stop Response */
		GtpV1_MBMSSessionStopResponse = 119,
		/** MBMS Session Update Request */
		GtpV1_MBMSSessionUpdateRequest = 120,
		/** MBMS Session Update Response */
		GtpV1_MBMSSessionUpdateResponse = 121,
		/** MS Info Change Request */
		GtpV1_MSInfoChangeRequest = 128,
		/** MS Info Change Response */
		GtpV1_MSInfoChangeResponse = 129,
		/** Data Record Transfer Request */
		GtpV1_DataRecordTransferRequest = 240,
		/** Data Record Transfer Response */
		GtpV1_DataRecordTransferResponse = 241,
		/** End Marker */
		GtpV1_EndMarker = 254,
		/** G-PDU */
		GtpV1_GPDU = 255
	};

	/**
	 * @class GtpV1Layer
	 * A class representing the [GTP v1](https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol) protocol.
	 */
	class GtpV1Layer : public Layer
	{
	private:
		struct gtpv1_header_extra
		{
			uint16_t sequenceNumber;
			uint8_t npduNumber;
			uint8_t nextExtensionHeader;
		};

		gtpv1_header_extra* getHeaderExtra() const;

		void init(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum,
		          uint8_t npduNum);

	public:
		/**
		 * @class GtpExtension
		 * A class that represents [GTP header extensions](https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol)
		 */
		class GtpExtension
		{
			friend class GtpV1Layer;

		private:
			uint8_t* m_Data;
			size_t m_DataLen;
			uint8_t m_ExtType;

			GtpExtension(uint8_t* data, size_t dataLen, uint8_t type);

			void setNextHeaderType(uint8_t nextHeaderType);

			static GtpExtension createGtpExtension(uint8_t* data, size_t dataLen, uint8_t extType, uint16_t content);

		public:
			/**
			 * An empty c'tor that creates an empty object, meaning one that isNull() returns "true")
			 */
			GtpExtension();

			/**
			 * A copy c'tor for this class
			 * @param[in] other The GTP extension to copy from
			 */
			GtpExtension(const GtpExtension& other);

			/**
			 * An assignment operator for this class
			 * @param[in] other The extension to assign from
			 * @return A reference to the assignee
			 */
			GtpExtension& operator=(const GtpExtension& other);

			/**
			 * @return Instances of this class may be initialized as empty, meaning they don't contain any data. In
			 * these cases this method returns true
			 */
			bool isNull() const;

			/**
			 * @return The extension type. If the object is empty a value of zero is returned
			 */
			uint8_t getExtensionType() const;

			/**
			 * @return The total length of the extension including the length and next extension type fields.
			 * If the object is empty a value of zero is returned
			 */
			size_t getTotalLength() const;

			/**
			 * @return The length of the extension's content, excluding the extension length and next extension type
			 * fields. If the object is empty a value of zero is returned
			 */
			size_t getContentLength() const;

			/**
			 * @return A byte array that includes the extension's content. The length of this array can be determined by
			 * getContentLength(). If the object is empty a null value is returned
			 */
			uint8_t* getContent() const;

			/**
			 * @return The extension type of the next header. If there are no more header extensions or if this object
			 * is empty a value of zero is returned
			 */
			uint8_t getNextExtensionHeaderType() const;

			/**
			 * @return An instance of this class representing the next extension header, if exists in the message. If
			 * there are no more header extensions or if this object is empty an empty instance of GtpExtension is
			 * returned, meaning one that GtpExtension#isNull() returns "true"
			 */
			GtpExtension getNextExtension() const;
		};  // GtpExtension

		virtual ~GtpV1Layer()
		{}

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		GtpV1Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, GTPv1)
		{}

		/**
		 * A constructor that creates a new GTPv1 layer and sets the message type and the TEID value
		 * @param[in] messageType The GTPv1 message type to be set in the newly created layer
		 * @param[in] teid The TEID value to be set in the newly created layer
		 */
		GtpV1Layer(GtpV1MessageType messageType, uint32_t teid);

		/**
		 * A constructor that creates a new GTPv1 layer and sets various parameters
		 * @param[in] messageType The GTPv1 message type to be set in the newly created layer
		 * @param[in] teid The TEID value to be set in the newly created layer
		 * @param[in] setSeqNum A flag indicating whether to set a sequence number. If set to "false" then the parameter
		 * "seqNum" will be ignored
		 * @param[in] seqNum The sequence number to be set in the newly created later. If "setSeqNum" is set to false
		 * this parameter will be ignored
		 * @param[in] setNpduNum A flag indicating whether to set the N-PDU number. If set to "false" then the parameter
		 * "npduNum" will be ignored
		 * @param[in] npduNum The N-PDU number to be set in the newly created later. If "setNpduNum" is set to false
		 * this parameter will be ignored
		 */
		GtpV1Layer(GtpV1MessageType messageType, uint32_t teid, bool setSeqNum, uint16_t seqNum, bool setNpduNum,
		           uint8_t npduNum);

		/**
		 * A static method that takes a byte array and detects whether it is a GTP v1 message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as GTP v1 message (GTP-C or GTP-U)
		 */
		static bool isGTPv1(const uint8_t* data, size_t dataSize);

		/**
		 * @return The GTP v1 common header structure. Notice this points directly to the data, so every change will
		 * change the actual packet data
		 */
		gtpv1_header* getHeader() const
		{
			return (gtpv1_header*)m_Data;
		}

		/**
		 * Get the sequence number if exists on the message (sequence number is an optional field in GTP messages)
		 * @param[out] seqNumber Set with the sequence number value if exists in the layer. Otherwise remains unchanged
		 * @return True if the sequence number field exists in layer, in which case seqNumber is set with the value.
		 * Or false otherwise
		 */
		bool getSequenceNumber(uint16_t& seqNumber) const;

		/**
		 * Set a sequence number
		 * @param[in] seqNumber The sequence number to set
		 * @return True if the value was set successfully, false otherwise. In case of failure a corresponding error
		 * message will be written to log
		 */
		bool setSequenceNumber(const uint16_t seqNumber);

		/**
		 * Get the N-PDU number if exists on the message (N-PDU number is an optional field in GTP messages)
		 * @param[out] npduNum Set with the N-PDU number value if exists in the layer. Otherwise remains unchanged
		 * @return True if the N-PDU number field exists in layer, in which case npduNum is set with the value.
		 * Or false otherwise
		 */
		bool getNpduNumber(uint8_t& npduNum) const;

		/**
		 * Set an N-PDU number
		 * @param[in] npduNum The N-PDU number to set
		 * @return True if the value was set successfully, false otherwise. In case of failure a corresponding error
		 * message will be written to log
		 */
		bool setNpduNumber(const uint8_t npduNum);

		/**
		 * Get the type of the next header extension if exists on the message (extensions are optional in GTP messages)
		 * @param[out] nextExtType Set with the next header extension type if exists in layer. Otherwise remains
		 * unchanged
		 * @return True if the message contains header extensions, in which case nextExtType is set to the next
		 * header extension type. If there are no header extensions false is returned and nextExtType remains unchanged
		 */
		bool getNextExtensionHeaderType(uint8_t& nextExtType) const;

		/**
		 * @return An object that represents the next extension header, if exists in the message. If there are no
		 * extensions an empty object is returned, meaning an object which GtpExtension#isNull() returns "true"
		 */
		GtpExtension getNextExtension() const;

		/**
		 * Add a GTPv1 header extension. It is assumed that the extension is 4 bytes in length and its content is 2
		 * bytes in length. If you need a different content size please reach out to me. This method takes care of
		 * extending the layer to make room for the new extension and also sets the relevant flags and fields
		 * @param[in] extensionType The type of the new extension
		 * @param[in] extensionContent A 2-byte long content
		 * @return An object representing the newly added extension. If there was an error adding the extension a null
		 * object will be returned (meaning GtpExtension#isNull() will return "true") and a corresponding error message
		 * will be written to log
		 */
		GtpExtension addExtension(uint8_t extensionType, uint16_t extensionContent);

		/**
		 * @return The message type of this GTP packet
		 */
		GtpV1MessageType getMessageType() const;

		/**
		 * @return A string representation of the packet's message type
		 */
		std::string getMessageTypeAsString() const;

		/**
		 * @return True if this is a GTP-U message, false otherwise
		 */
		bool isGTPUMessage() const;

		/**
		 * @return True if this is a GTP-C message, false otherwise
		 */
		bool isGTPCMessage() const;

		/**
		 * A static method that checks whether the port is considered as GTPv1
		 * @param[in] port The port number to be checked
		 * @return True if the port matches those associated with the BGP protocol
		 */
		static bool isGTPv1Port(uint16_t port)
		{
			return port == 2152 /* GTP-U */ || port == 2123 /* GTP-C */;
		}

		// implement abstract methods

		/**
		 * Identifies the following next layers for GTP-U packets: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return The size of the GTP header. For GTP-C packets the size is determined by the value of
		 * gtpv1_header#messageLength and for GTP-U the size only includes the GTP header itself (meaning
		 * the size of gtpv1_header plus the size of the optional fields such as sequence number, N-PDU
		 * or extensions if exist)
		 */
		size_t getHeaderLen() const;

		/**
		 * Calculate the following fields:
		 * - gtpv1_header#messageLength
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelTransportLayer;
		}
	};
}  // namespace vanhooks::net
// ---- end GtpLayer.h ----

