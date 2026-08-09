#pragma once

// ===== Consolidated header: L2Layers.h =====
// Merges: EthLayer, EthDot3Layer, LLCLayer, VlanLayer, MplsLayer, ArpLayer, StpLayer, WakeOnLanLayer, NullLoopbackLayer, SllLayer, Sll2Layer, NflogLayer, PPPoELayer, NdpLayer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "PacketCore.h"
#include "Common.h"
#include "L3Layers.h"

// ---- begin EthLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct ether_header
	 * Represents an Ethernet II header
	 */
#pragma pack(push, 1)
	struct ether_header
	{
		/** Destination MAC */
		uint8_t dstMac[6];
		/** Source MAC */
		uint8_t srcMac[6];
		/** EtherType */
		uint16_t etherType;
	};
#pragma pack(pop)

	/* Ethernet protocol ID's */

	/** IP */
#define VH_ETHERTYPE_IP 0x0800
	/** Address resolution */
#define VH_ETHERTYPE_ARP 0x0806
	/** Transparent Ethernet Bridging */
#define VH_ETHERTYPE_ETHBRIDGE 0x6558
	/** Reverse ARP */
#define VH_ETHERTYPE_REVARP 0x8035
	/** AppleTalk protocol */
#define VH_ETHERTYPE_AT 0x809B
	/** AppleTalk ARP */
#define VH_ETHERTYPE_AARP 0x80F3
	/** IEEE 802.1Q VLAN tagging */
#define VH_ETHERTYPE_VLAN 0x8100
	/** IPX */
#define VH_ETHERTYPE_IPX 0x8137
	/** IP protocol version 6 */
#define VH_ETHERTYPE_IPV6 0x86dd
	/** used to test interfaces */
#define VH_ETHERTYPE_LOOPBACK 0x9000
	/** PPPoE discovery */
#define VH_ETHERTYPE_PPPOED 0x8863
	/** PPPoE session */
#define VH_ETHERTYPE_PPPOES 0x8864
	/** MPLS */
#define VH_ETHERTYPE_MPLS 0x8847
	/** Point-to-point protocol (PPP) */
#define VH_ETHERTYPE_PPP 0x880B
	/** RDMA over Converged Ethernet (RoCEv1) */
#define VH_ETHERTYPE_ROCEV1 0x8915
	/** IEEE 802.1ad Provider Bridge, Q-in-Q */
#define VH_ETHERTYPE_IEEE_802_1AD 0x88A8
	/** Wake on LAN */
#define VH_ETHERTYPE_WAKE_ON_LAN 0x0842

	/**
	 * @class EthLayer
	 * Represents an Ethernet II protocol layer
	 */
	class EthLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		EthLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, Ethernet)
		{}

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		EthLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Ethernet)
		{}

		/**
		 * A constructor that creates a new Ethernet header and allocates the data
		 * @param[in] sourceMac The source MAC address
		 * @param[in] destMac The destination MAC address
		 * @param[in] etherType The EtherType to be used. It's an optional parameter, a value of 0 will be set if not
		 * provided
		 */
		EthLayer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t etherType = 0);

		~EthLayer()
		{}

		/**
		 * Get a pointer to the Ethernet header. Notice this points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the ether_header
		 */
		inline ether_header* getEthHeader() const
		{
			return (ether_header*)m_Data;
		}

		/**
		 * Get the source MAC address
		 * @return The source MAC address
		 */
		inline MacAddress getSourceMac() const
		{
			return MacAddress(getEthHeader()->srcMac);
		}

		/**
		 * Set source MAC address
		 * @param sourceMac Source MAC to set
		 */
		inline void setSourceMac(const MacAddress& sourceMac)
		{
			sourceMac.copyTo(getEthHeader()->srcMac);
		}

		/**
		 * Get the destination MAC address
		 * @return The destination MAC address
		 */
		inline MacAddress getDestMac() const
		{
			return MacAddress(getEthHeader()->dstMac);
		}

		/**
		 * Set destination MAC address
		 * @param destMac Destination MAC to set
		 */
		inline void setDestMac(const MacAddress& destMac)
		{
			destMac.copyTo(getEthHeader()->dstMac);
		}

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer, PPPoESessionLayer,
		 * PPPoEDiscoveryLayer, MplsLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of ether_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(ether_header);
		}

		/**
		 * Calculate ether_header#etherType for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Ethernet II packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Ethernet II packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);
	};

}  // namespace vanhooks::net
// ---- end EthLayer.h ----

// ---- begin EthDot3Layer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct ether_dot3_header
	 * Represents an IEEE 802.3 Ethernet header
	 */
#pragma pack(push, 1)
	struct ether_dot3_header
	{
		/** Destination MAC */
		uint8_t dstMac[6];
		/** Source MAC */
		uint8_t srcMac[6];
		/** EtherType */
		uint16_t length;
	};
#pragma pack(pop)

	/**
	 * @class EthDot3Layer
	 * Represents an IEEE 802.3 Ethernet protocol layer
	 */
	class EthDot3Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_dot3_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		EthDot3Layer(uint8_t* data, size_t dataLen, Packet* packet)
		    : Layer(data, dataLen, nullptr, packet, EthernetDot3)
		{}

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		EthDot3Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, EthernetDot3)
		{}

		/**
		 * A constructor that creates a new IEEE 802.3 Ethernet header and allocates the data
		 * @param[in] sourceMac The source MAC address
		 * @param[in] destMac The destination MAC address
		 * @param[in] length The frame length
		 */
		EthDot3Layer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t length);

		~EthDot3Layer()
		{}

		/**
		 * Get a pointer to the Ethernet header. Notice this points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the ether_header
		 */
		ether_dot3_header* getEthHeader() const
		{
			return (ether_dot3_header*)m_Data;
		}

		/**
		 * Get the source MAC address
		 * @return The source MAC address
		 */
		MacAddress getSourceMac() const
		{
			return MacAddress(getEthHeader()->srcMac);
		}

		/**
		 * Set source MAC address
		 * @param sourceMac Source MAC to set
		 */
		void setSourceMac(const MacAddress& sourceMac)
		{
			sourceMac.copyTo(getEthHeader()->srcMac);
		}

		/**
		 * Get the destination MAC address
		 * @return The destination MAC address
		 */
		MacAddress getDestMac() const
		{
			return MacAddress(getEthHeader()->dstMac);
		}

		/**
		 * Set destination MAC address
		 * @param destMac Destination MAC to set
		 */
		void setDestMac(const MacAddress& destMac)
		{
			destMac.copyTo(getEthHeader()->dstMac);
		}

		// implement abstract methods

		/**
		 * Parses next layer
		 */
		void parseNextLayer();

		/**
		 * @return Size of ether_dot3_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(ether_dot3_header);
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

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an IEEE 802.3 Eth packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an IEEE 802.3 Eth packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);
	};

}  // namespace vanhooks::net
// ---- end EthDot3Layer.h ----

// ---- begin LLCLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
#pragma pack(push, 1)
	/**
	 * @struct llc_header
	 * Logical Link Control (LLC) header
	 */
	struct llc_header
	{
		/// Destination Service Access Point
		uint8_t dsap,
		    /// Source Service Access Point
		    ssap,
		    /// Control Field
		    control;
	};
#pragma pack(pop)

	/**
	 * @class LLCLayer
	 * Represents Logical Link Control layer messages
	 */
	class LLCLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to llc_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		LLCLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, LLC)
		{}

		/**
		 * A constructor that creates the LLC layer from provided values
		 * @param[in] dsap Destination Service Access Point
		 * @param[in] ssap Source Service Access Point
		 * @param[in] control Control Field
		 */
		LLCLayer(uint8_t dsap, uint8_t ssap, uint8_t control);

		/**
		 * Get a pointer to Logical Link Control (LLC) layer header
		 * @return Pointer to LLC header
		 */
		inline llc_header* getLlcHeader() const
		{
			return (llc_header*)m_Data;
		};

		// overridden methods

		/// Parses the next layer. Currently only STP supported as next layer
		void parseNextLayer();

		/// Does nothing for this layer
		void computeCalculateFields()
		{}

		/**
		 * @return Get the size of the LLC header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(llc_header);
		}

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;

		/**
		 * @return The OSI layer level of LLC (Data Link Layer).
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an LLC packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an LLC packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);
	};

}  // namespace vanhooks::net
// ---- end LLCLayer.h ----

// ---- begin VlanLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct vlan_header
	 * Represents a VLAN header
	 */
#pragma pack(push, 1)
	struct vlan_header
	{
		/**
		 @verbatim
		 0               1               2
		 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 |Prio |C|         VLAN ID       |
		 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		 @endverbatim
		 */
		uint16_t vlan;
		/** Ethernet type for next layer */
		uint16_t etherType;
	};
#pragma pack(pop)

	/**
	 * @class VlanLayer
	 * Represents a VLAN tunnel layer
	 */
	class VlanLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		VlanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, VLAN)
		{}

		/**
		 * A constructor that allocates a new VLAN header
		 * @param[in] vlanID VLAN ID
		 * @param[in] cfi CFI value
		 * @param[in] priority Priority value
		 * @param[in] etherType Protocol EtherType of the next layer. It's an optional parameter, a value of 0 will be
		 * set if not provided
		 */
		VlanLayer(const uint16_t vlanID, bool cfi, uint8_t priority, uint16_t etherType = 0);

		~VlanLayer()
		{}

		/**
		 * Get a pointer to the VLAN header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the vlan_header
		 */
		vlan_header* getVlanHeader() const
		{
			return (vlan_header*)m_Data;
		}

		/**
		 * Get the VLAN ID value. This method differs from vlan_header#vlanID because vlan_header#vlanID is 12 bits long
		 * in a 16 bit field. This methods extracts only the 12 bit relevant for the VLAN ID
		 * @return VLAN ID value
		 * @todo Verify it works in big endian machines as well
		 */
		uint16_t getVlanID() const;

		/**
		 * @return The CFI bit value
		 * @todo Verify it works in big endian machines as well
		 */
		uint8_t getCFI() const;

		/**
		 * @return The priority value
		 * @todo Verify it works in big endian machines as well
		 */
		uint8_t getPriority() const;

		/**
		 * Set VLAN ID. This method differs from setting vlan_header#vlanID because vlan_header#vlanID is 12 bits long
		 * in a 16 bit field. This methods sets only the 12 bit relevant for the VLAN ID
		 * @param[in] id The VLAN ID to set
		 * @todo Verify it works in big endian machines as well
		 */
		void setVlanID(uint16_t id);

		/**
		 * Set CFI bit
		 * @param[in] cfi The CFI bit to set
		 * @todo Verify it works in big endian machines as well
		 */
		void setCFI(bool cfi);

		/**
		 * Set priority value
		 * @param[in] priority The priority value to set
		 * @todo Verify it works in big endian machines as well
		 */
		void setPriority(uint8_t priority);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer, MplsLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of vlan_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(vlan_header);
		}

		/**
		 * Calculate the EtherType for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end VlanLayer.h ----

// ---- begin MplsLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class MplsLayer
	 * Represents a MPLS (Multi-Protocol Label Switching) layer
	 */
	class MplsLayer : public Layer
	{
	private:
#pragma pack(push, 1)
		struct mpls_header
		{
			uint16_t hiLabel;
			uint8_t misc;
			uint8_t ttl;
		};
#pragma pack(pop)

		mpls_header* getMplsHeader() const
		{
			return (mpls_header*)m_Data;
		}

	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		MplsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, MPLS)
		{}

		/**
		 * A constructor that allocates a new MPLS header
		 * @param[in] mplsLabel MPLS label
		 * @param[in] ttl Time-to-leave value
		 * @param[in] experimentalUseValue Experimental use value
		 * @param[in] bottomOfStack Bottom-of-stack value which indicate whether the next layer will also be a MPLS
		 * label or not
		 */
		MplsLayer(uint32_t mplsLabel, uint8_t ttl, uint8_t experimentalUseValue, bool bottomOfStack);

		virtual ~MplsLayer()
		{}

		/**
		 * @return TTL value of the MPLS header
		 */
		uint8_t getTTL() const
		{
			return getMplsHeader()->ttl;
		}

		/**
		 * Set the TTL value
		 * @param[in] ttl The TTL value to set
		 */
		void setTTL(uint8_t ttl)
		{
			getMplsHeader()->ttl = ttl;
		}

		/**
		 * Get an indication whether the next layer is also be a MPLS label or not
		 * @return True if it's the last MPLS layer, false otherwise
		 */
		bool isBottomOfStack() const;

		/**
		 * Set the bottom-of-stack bit in the MPLS label
		 * @param[in] val Set or unset the bit
		 */
		void setBottomOfStack(bool val);

		/**
		 * @return The exp value (3 bits) of the MPLS label
		 */
		uint8_t getExperimentalUseValue() const;

		/**
		 * Set the exp value (3 bits) of the MPLS label
		 * @param[in] val The exp value to set. val must be a valid number meaning between 0 and 7 (inclusive)
		 * @return True if exp value was set successfully or false if val has invalid value
		 */
		bool setExperimentalUseValue(uint8_t val);

		/**
		 * @return The MPLS label value (20 bits)
		 */
		uint32_t getMplsLabel() const;

		/**
		 * Set the MPLS label (20 bits)
		 * @param[in] label The label to set. label must be a valid number meaning between 0 and 0xFFFFF (inclusive)
		 * @return True if label was set successfully or false if label has invalid value
		 */
		bool setMplsLabel(uint32_t label);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, MplsLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of MPLS header (4 bytes)
		 */
		size_t getHeaderLen() const
		{
			return sizeof(mpls_header);
		}

		/**
		 * Set/unset the bottom-of-stack bit according to next layer: if it's a MPLS layer then bottom-of-stack will be
		 * unset. If it's not a MPLS layer this bit will be set
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end MplsLayer.h ----

// ---- begin ArpLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct arphdr
	 * Represents an ARP protocol header
	 */
#pragma pack(push, 1)
	struct arphdr
	{
		/** Hardware type (HTYPE) */
		uint16_t hardwareType;
		/** Protocol type (PTYPE). The permitted PTYPE values share a numbering space with those for EtherType */
		uint16_t protocolType;
		/** Hardware address length (HLEN). For IPv4, this has the value 0x0800 */
		uint8_t hardwareSize;
		/** Protocol length (PLEN). Length (in octets) of addresses used in the upper layer protocol. (The upper layer
		 * protocol specified in PTYPE.) IPv4 address size is 4 */
		uint8_t protocolSize;
		/** Specifies the operation that the sender is performing: 1 (::ARP_REQUEST) for request, 2 (::ARP_REPLY) for
		 * reply */
		uint16_t opcode;
		/** Sender hardware address (SHA) */
		uint8_t senderMacAddr[6];
		/** Sender protocol address (SPA) */
		uint32_t senderIpAddr;
		/** Target hardware address (THA) */
		uint8_t targetMacAddr[6];
		/** Target protocol address (TPA) */
		uint32_t targetIpAddr;
	};
#pragma pack(pop)

	/**
	 * An enum for ARP message type
	 */
	enum ArpOpcode
	{
		ARP_REQUEST = 0x0001,  ///< ARP request
		ARP_REPLY = 0x0002     ///< ARP reply (response)
	};

	/**
	 * @class ArpLayer
	 * Represents an ARP protocol layer. Currently only IPv4 ARP messages are supported
	 */
	class ArpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref arphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		ArpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, ARP)
		{
			m_DataLen = sizeof(arphdr);
		}

		/**
		 * A constructor that allocates a new ARP header
		 * @param[in] opCode ARP message type (ARP request or ARP reply)
		 * @param[in] senderMacAddr The sender MAC address (will be put in arphdr#senderMacAddr)
		 * @param[in] targetMacAddr The target MAC address (will be put in arphdr#targetMacAddr)
		 * @param[in] senderIpAddr The sender IP address (will be put in arphdr#senderIpAddr)
		 * @param[in] targetIpAddr The target IP address (will be put in arphdr#targetIpAddr)
		 */
		ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr,
		         const IPv4Address& senderIpAddr, const IPv4Address& targetIpAddr);

		~ArpLayer()
		{}

		/**
		 * Get a pointer to the ARP header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the @ref arphdr
		 */
		inline arphdr* getArpHeader() const
		{
			return (arphdr*)m_Data;
		}

		/**
		 * Get the sender hardware address (SHA) in the form of MacAddress
		 * @return A MacAddress containing the sender hardware address (SHA)
		 */
		inline MacAddress getSenderMacAddress() const
		{
			return MacAddress(getArpHeader()->senderMacAddr);
		}

		/**
		 * Get the target hardware address (THA) in the form of MacAddress
		 * @return A MacAddress containing the target hardware address (THA)
		 */
		inline MacAddress getTargetMacAddress() const
		{
			return MacAddress(getArpHeader()->targetMacAddr);
		}

		/**
		 * Get the sender protocol address (SPA) in the form of IPv4Address
		 * @return An IPv4Address containing the sender protocol address (SPA)
		 */
		inline IPv4Address getSenderIpAddr() const
		{
			return getArpHeader()->senderIpAddr;
		}

		/**
		 * Get the target protocol address (TPA) in the form of IPv4Address
		 * @return An IPv4Address containing the target protocol address (TPA)
		 */
		inline IPv4Address getTargetIpAddr() const
		{
			return getArpHeader()->targetIpAddr;
		}

		// implement abstract methods

		/**
		 * Does nothing for this layer (ArpLayer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return The size of @ref arphdr
		 */
		size_t getHeaderLen() const
		{
			return sizeof(arphdr);
		}

		/**
		 * Calculate the following fields:
		 * - @ref arphdr#hardwareType = Ethernet (1)
		 * - @ref arphdr#hardwareSize = 6
		 * - @ref arphdr#protocolType = ETHERTYPE_IP (assume IPv4 over ARP)
		 * - @ref arphdr#protocolSize = 4 (assume IPv4 over ARP)
		 * - if it's an ARP request: @ref arphdr#targetMacAddr = MacAddress("00:00:00:00:00:00")
		 */
		void computeCalculateFields();

		/**
		 * Is this packet an ARP request?
		 */
		bool isRequest() const;

		/**
		 * Is this packet an ARP reply?
		 */
		bool isReply() const;

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelNetworkLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end ArpLayer.h ----

// ---- begin StpLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

/**
 * @struct stp_tcn_bpdu
 * Represents payload of network changes announcements of BPDU
 */
#pragma pack(push, 1)
	struct stp_tcn_bpdu
	{
		/// Protocol ID. Fixed at 0x0, which represents IEEE 802.1d
		uint16_t protoId;
		/// Protocol version. 0x0 for STP, 0x2 for RSTP, 0x3 for MSTP
		uint8_t version;
		/// Type of the BPDU. 0x0 for configuration, 0x2 for RSTP/MSTP, 0x80 for TCN
		uint8_t type;
	};
#pragma pack(pop)

	/// Spanning Tree protocol common header
	typedef stp_tcn_bpdu stp_header;

/**
 * @struct stp_conf_bpdu
 * Represents payload configuration of BPDU for STP
 */
#pragma pack(push, 1)
	struct stp_conf_bpdu : stp_tcn_bpdu
	{
		/// Flag for indicate purpose of BPDU
		uint8_t flag;
		/// Root bridge ID
		uint64_t rootId;
		/// Cost of path
		uint32_t pathCost;
		/// Bridge ID
		uint64_t bridgeId;
		/// Port ID
		uint16_t portId;
		/// Age of the BPDU
		uint16_t msgAge;
		/// Maximum age of the BPDU
		uint16_t maxAge;
		/// BPDU transmission interval
		uint16_t helloTime;
		/// Delay for STP
		uint16_t forwardDelay;
	};
#pragma pack(pop)

/**
 * @struct rstp_conf_bpdu
 * Represents payload configuration of BPDU for Rapid STP (RSTP)
 */
#pragma pack(push, 1)
	struct rstp_conf_bpdu : stp_conf_bpdu
	{
		/// Version1 length. The value is 0x0
		uint8_t version1Len;
	};
#pragma pack(pop)

/**
 * @struct mstp_conf_bpdu
 * Represents payload configuration of BPDU for Multiple STP (MSTP)
 */
#pragma pack(push, 1)
	struct mstp_conf_bpdu : rstp_conf_bpdu
	{
		/// Version3 length.
		uint16_t version3Len;
		/// Configuration id format selector
		uint8_t mstConfigFormatSelector;
		/// Configuration id name
		uint8_t mstConfigName[32];
		/// Configuration id revision
		uint16_t mstConfigRevision;
		/// Configuration id digest
		uint8_t mstConfigDigest[16];
		/// CIST internal root path cost
		uint32_t irpc;
		/// CIST bridge id
		uint64_t cistBridgeId;
		/// CIST remaining hop count
		uint8_t remainId;
	};
#pragma pack(pop)

/**
 * @struct msti_conf_msg
 * Represents MSTI configuration messages. Each message contains 16 bytes and MSTP can contain 0 to 64 MSTI messages.
 */
#pragma pack(push, 1)
	struct msti_conf_msg
	{
		/// MSTI flags
		uint8_t flags;
		/// Regional root switching id (Priority (4 bits) + ID (12 bits) + Regional root (48 bits - MAC address))
		uint64_t regionalRootId;
		/// Total path cost from local port to regional port
		uint32_t pathCost;
		/// Priority value of switching device
		uint8_t bridgePriority;
		/// Priority value of port
		uint8_t portPriority;
		/// Remaining hops of BPDU
		uint8_t remainingHops;
	};
#pragma pack(pop)

	/**
	 * @class StpLayer
	 * Represents an Spanning Tree Protocol Layer
	 */
	class StpLayer : public Layer
	{
	protected:
		StpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, STP)
		{}

		explicit StpLayer(size_t dataLen)
		{
			m_DataLen = dataLen;
			m_Data = new uint8_t[dataLen];
			memset(m_Data, 0, dataLen);
			m_Protocol = STP;
		}

		static vanhooks::net::MacAddress IDtoMacAddress(uint64_t id);
		static uint64_t macAddressToID(const vanhooks::net::MacAddress& addr);

	public:
		/// STP protocol uses "01:80:C2:00:00:00" multicast address as destination MAC
		static vanhooks::net::MacAddress StpMulticastDstMAC;
		/// STP Uplink Fast protocol uses "01:00:0C:CD:CD:CD" as destination MAC
		static vanhooks::net::MacAddress StpUplinkFastMulticastDstMAC;

		/**
		 * Get a pointer to base Spanning tree header
		 * @return A pointer to spanning tree header
		 */
		stp_header* getStpHeader() const
		{
			return (stp_header*)(m_Data);
		}

		/**
		 * Returns the protocol id. Fixed at 0x0 for STP messages which represents IEEE 802.1d
		 * @return ID of the protocol
		 */
		uint16_t getProtoId() const
		{
			return getStpHeader()->protoId;
		}

		/**
		 * Sets the protocol id
		 * @param[in] value ID of the protocol
		 */
		void setProtoId(uint16_t value)
		{
			getStpHeader()->protoId = value;
		}

		/**
		 * Returns the version. Fixed at 0x0 for STP messages
		 * @return Version number
		 */
		uint8_t getVersion() const
		{
			return getStpHeader()->version;
		}

		/**
		 * Sets the version
		 * @param[in] value Version number
		 */
		void setVersion(uint8_t value)
		{
			getStpHeader()->version = value;
		}

		/**
		 * Returns the type of configuration message.
		 * @return Type of configuration message
		 */
		uint8_t getType() const
		{
			return getStpHeader()->type;
		}

		/**
		 * Sets the type of configuration message
		 * @param[in] value Type of configuration message
		 */
		void setType(uint8_t value)
		{
			getStpHeader()->type = value;
		}

		// overridden methods

		/**
		 * @return The size of STP packet
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields()
		{}

		/**
		 * @return The OSI layer level of STP (Data Link Layer).
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/**
		 * A method to create STP layer from existing packet
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return A newly allocated STP layer of one of the following types (according to the message type):
		 * StpConfigurationBPDULayer, StpTopologyChangeBPDULayer, RapidStpLayer, MultipleStpLayer
		 */
		static StpLayer* parseStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);
	};

	/**
	 * @class StpTopologyChangeBPDULayer
	 * Represents network topology change BPDU message of Spanning Tree Protocol
	 */
	class StpTopologyChangeBPDULayer : public StpLayer
	{
	protected:
		explicit StpTopologyChangeBPDULayer(size_t dataLen) : StpLayer(dataLen)
		{}

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StpTopologyChangeBPDULayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : StpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * Empty c'tor to create a new network topology change (TCN) BPDU layer.
		 * Initializes the protocol identifier, version and STP type fields with correct values
		 */
		StpTopologyChangeBPDULayer();

		/**
		 * Get a pointer to network topology change (TCN) BPDU message
		 * @return A pointer to TCN BPDU message
		 */
		stp_tcn_bpdu* getStpTcnHeader()
		{
			return getStpHeader();
		}

		// overridden methods

		/**
		 * @return The size of STP TCN message
		 */
		size_t getHeaderLen() const
		{
			return sizeof(stp_tcn_bpdu);
		}

		/// Parses next layer
		void parseNextLayer();

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const
		{
			return "Spanning Tree Topology Change Notification";
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree Topology Change BPDU packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(stp_tcn_bpdu);
		}
	};

	/**
	 * @class StpConfigurationBPDULayer
	 * Represents configuration BPDU message of Spanning Tree Protocol
	 */
	class StpConfigurationBPDULayer : public StpTopologyChangeBPDULayer
	{
	protected:
		explicit StpConfigurationBPDULayer(size_t dataLen) : StpTopologyChangeBPDULayer(dataLen)
		{}

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		StpConfigurationBPDULayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : StpTopologyChangeBPDULayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * Empty c'tor to create a new configuration BPDU layer.
		 * Initializes the protocol identifier, version and STP type fields with correct values
		 */
		StpConfigurationBPDULayer();

		/**
		 * Get a pointer to configuration BPDU message
		 * @return A pointer to configuration BPDU message
		 */
		stp_conf_bpdu* getStpConfHeader() const
		{
			return (stp_conf_bpdu*)(m_Data);
		}

		/**
		 * Returns the flags of configuration message which indicates purpose of BPDU
		 * @return Flags of the configuration message
		 */
		uint8_t getFlag() const
		{
			return getStpConfHeader()->flag;
		}

		/**
		 * Returns the flags of configuration message which indicates purpose of BPDU
		 * @param[in] value Flags of the configuration message
		 */
		void setFlag(uint8_t value)
		{
			getStpConfHeader()->flag = value;
		}

		/**
		 * Returns the root bridge identifier
		 * @return Root bridge identifier
		 */
		uint64_t getRootId() const;

		/**
		 * Sets the root bridge identifier
		 * @param[in] value Root bridge identifier
		 */
		void setRootId(uint64_t value);

		/**
		 * Returns the priority of root bridge
		 * @return Priority of root bridge
		 */
		uint16_t getRootPriority() const;

		/**
		 * Sets the priority of root bridge
		 * @param[in] value Priority of root bridge
		 */
		void setRootPriority(uint16_t value);

		/**
		 * Returns the system identifier extension of root bridge
		 * @return System extension of root bridge
		 */
		uint16_t getRootSystemIDExtension() const;

		/**
		 * Sets the system identifier extension of root bridge
		 * @param[in] value System extension of root bridge
		 */
		void setRootSystemIDExtension(uint16_t value);

		/**
		 * Returns the system identifier of root bridge
		 * @return System identifier of root bridge
		 */
		vanhooks::net::MacAddress getRootSystemID() const
		{
			return IDtoMacAddress(getRootId());
		}

		/**
		 * Sets the system identifier of root bridge
		 * @param[in] value System identifier of root bridge
		 */
		void setRootSystemID(const vanhooks::net::MacAddress& value);

		/**
		 * Returns the value of the cost of path
		 * @return Cost of path
		 */
		uint32_t getPathCost() const;

		/**
		 * Sets the value of the cost of path
		 * @param[in] value Cost of path
		 */
		void setPathCost(uint32_t value);

		/**
		 * Returns the bridge identifier
		 * @return Bridge identifier
		 */
		uint64_t getBridgeId() const;

		/**
		 * Sets the bridge identifier
		 * @param[in] value Bridge identifier
		 */
		void setBridgeId(uint64_t value);

		/**
		 * Returns the priority of bridge
		 * @return Priority of bridge
		 */
		uint16_t getBridgePriority() const;

		/**
		 * Sets the priority of bridge
		 * @param[in] value Priority of bridge
		 */
		void setBridgePriority(uint16_t value);

		/**
		 * Returns the system identifier extension of bridge
		 * @return System extension of bridge
		 */
		uint16_t getBridgeSystemIDExtension() const;

		/**
		 * Sets the system identifier extension of bridge
		 * @param[in] value System extension of bridge
		 */
		void setBridgeSystemIDExtension(uint16_t value);

		/**
		 * Returns the system identifier of bridge
		 * @return System identifier of bridge
		 */
		vanhooks::net::MacAddress getBridgeSystemID() const
		{
			return IDtoMacAddress(getBridgeId());
		}

		/**
		 * Sets the system identifier of bridge
		 * @param[in] value System identifier of bridge
		 */
		void setBridgeSystemID(const vanhooks::net::MacAddress& value);

		/**
		 * Returns the port identifier
		 * @return Port identifier
		 */
		uint16_t getPortId() const;

		/**
		 * Sets the port identifier
		 * @param[in] value Port identifier
		 */
		void setPortId(uint16_t value);

		/**
		 * Returns age of the BPDU message
		 * @return Age of BPDU in seconds
		 */
		double getMessageAge() const;

		/**
		 * Sets age of the BPDU message
		 * @param[in] value Age of BPDU in seconds
		 */
		void setMessageAge(double value);

		/**
		 * Returns maximum age of the BPDU message
		 * @return Maximum age of BPDU in seconds
		 */
		double getMaximumAge() const;

		/**
		 * Sets maximum age of the BPDU message
		 * @param[in] value Maximum age of BPDU in seconds
		 */
		void setMaximumAge(double value);

		/**
		 * Returns the BPDU transmission interval
		 * @return Value of the transmission interval in seconds
		 */
		double getTransmissionInterval() const;

		/**
		 * Sets the BPDU transmission interval
		 * @param[in] value Value of the transmission interval in seconds
		 */
		void setTransmissionInterval(double value);

		/**
		 * Returns the delay for STP message
		 * @return Value of the forward delay in seconds
		 */
		double getForwardDelay() const;

		/**
		 * Sets the delay for STP message
		 * @param[in] value Value of the forward delay in seconds
		 */
		void setForwardDelay(double value);

		// overridden methods

		/**
		 * @return The size of STP configuration BPDU message
		 */
		size_t getHeaderLen() const
		{
			return sizeof(stp_conf_bpdu);
		}

		/// Parses next layer
		void parseNextLayer();

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const
		{
			return "Spanning Tree Configuration";
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Spanning Tree Configuration BPDU packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(stp_conf_bpdu);
		}
	};

	/**
	 * @class RapidStpLayer
	 * Represents Rapid Spanning Tree Protocol (RSTP)
	 */
	class RapidStpLayer : public StpConfigurationBPDULayer
	{
	protected:
		explicit RapidStpLayer(size_t dataLen) : StpConfigurationBPDULayer(dataLen)
		{}

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		RapidStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : StpConfigurationBPDULayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * Empty c'tor to create a new Rapid STP layer.
		 * Initializes the protocol identifier, version and STP type fields with correct values
		 */
		RapidStpLayer();

		/**
		 * Get a pointer to Rapid STP header
		 * @return A pointer to Rapid STP header
		 */
		rstp_conf_bpdu* getRstpConfHeader() const
		{
			return (rstp_conf_bpdu*)(m_Data);
		}

		/**
		 * Returns the length of version1 field. Fixed at 0x0 for Rapid STP
		 * @return Length of the version1 field
		 */
		uint8_t getVersion1Len() const
		{
			return getRstpConfHeader()->version1Len;
		}

		/**
		 * Returns the length of version1 field
		 * @param[in] value Length of the version1 field
		 */
		void setVersion1Len(uint8_t value)
		{
			getRstpConfHeader()->version1Len = value;
		}

		// overridden methods

		/**
		 * @return The size of Rapid STP message
		 */
		size_t getHeaderLen() const
		{
			return sizeof(rstp_conf_bpdu);
		}

		/// Parses next layer
		void parseNextLayer();

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const
		{
			return "Rapid Spanning Tree";
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Rapid STP packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(rstp_conf_bpdu);
		}
	};

	/**
	 * @class MultipleStpLayer
	 * Represents Multiple Spanning Tree Protocol (MSTP). It has limited capabilities (no crafting / limited editing)
	 * over MSTI configuration
	 */
	class MultipleStpLayer : public RapidStpLayer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		MultipleStpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : RapidStpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * Empty c'tor to create a new Multiple STP layer.
		 * Initializes the protocol identifier, version and STP type fields with correct values
		 */
		MultipleStpLayer();

		/**
		 * Get a pointer to Multiple STP header
		 * @return A pointer to Multiple STP header
		 */
		mstp_conf_bpdu* getMstpHeader() const
		{
			return (mstp_conf_bpdu*)(m_Data);
		}

		/**
		 * @return Length of version3 field
		 */
		uint16_t getVersion3Len() const;

		/**
		 * Sets the length of version3 field
		 * @param[in] value Length of version3 field
		 */
		void setVersion3Len(uint16_t value);

		/**
		 * Returns the configuration ID format selector
		 * @return Configuration ID of format selector
		 */
		uint8_t getMstConfigurationFormatSelector() const
		{
			return getMstpHeader()->mstConfigFormatSelector;
		}

		/**
		 * Sets the configuration ID format selector
		 * @param[in] value Configuration ID of format selector
		 */
		void setMstConfigurationFormatSelector(uint8_t value)
		{
			getMstpHeader()->mstConfigFormatSelector = value;
		}

		/**
		 * Returns the pointer to configuration name field
		 * @return Configuration name
		 */
		std::string getMstConfigurationName() const;

		/**
		 * Sets the configuration name field
		 * @param[in] value Configuration name. Length should be less than 32, if longer value provided first 32
		 * characters are used
		 */
		void setMstConfigurationName(const std::string& value);

		/**
		 * Returns the revision of configuration ID
		 * @return Revision of configuration ID
		 */
		uint16_t getMstConfigRevision() const;

		/**
		 * Sets the revision of configuration ID
		 * @param[in] value Revision of configuration ID
		 */
		void setMstConfigRevision(uint16_t value);

		/**
		 * Returns the pointer to configuration message digest. The field itself always 16 bytes long.
		 * @return A pointer to configuration digest
		 */
		uint8_t* getMstConfigDigest() const
		{
			return getMstpHeader()->mstConfigDigest;
		}

		/**
		 * Sets the pointer to configuration message digest. The field itself always 16 bytes long.
		 * @param[in] value Pointer to digest
		 * @param[in] len Length of the digest, should be less than 16. If longer first 16 bytes are used
		 */
		void setMstConfigDigest(const uint8_t* value, uint8_t len);

		/**
		 * Returns CIST internal root path cost
		 * @return Value of the internal root path cost
		 */
		uint32_t getCISTIrpc() const;

		/**
		 * Sets CIST internal root path cost
		 * @param[in] value Value of the internal root path cost
		 */
		void setCISTIrpc(uint32_t value);

		/**
		 * Returns CIST bridge identifier
		 * @return Value of the bridge identifier
		 */
		uint64_t getCISTBridgeId() const;

		/**
		 * Sets CIST bridge identifier
		 * @param[in] value Value of the bridge identifier
		 */
		void setCISTBridgeId(uint64_t value);

		/**
		 * Returns the priority of CIST bridge
		 * @return Priority of CIST bridge
		 */
		uint16_t getCISTBridgePriority() const;

		/**
		 * Sets the priority of CIST bridge
		 * @param[in] value Priority of CIST bridge
		 */
		void setCISTBridgePriority(uint16_t value);

		/**
		 * Returns the system identifier extension of CIST bridge
		 * @return System extension of CIST bridge
		 */
		uint16_t getCISTBridgeSystemIDExtension() const;

		/**
		 * Sets the system identifier extension of CIST bridge
		 * @param[in] value System extension of CIST bridge
		 */
		void setCISTBridgeSystemIDExtension(uint16_t value);

		/**
		 * Returns the system identifier of CIST bridge
		 * @return System identifier of CIST bridge
		 */
		vanhooks::net::MacAddress getCISTBridgeSystemID() const
		{
			return IDtoMacAddress(getCISTBridgeId());
		}

		/**
		 * Sets the system identifier of CIST bridge
		 * @param[in] value System identifier of CIST bridge
		 */
		void setCISTBridgeSystemID(const vanhooks::net::MacAddress& value);

		/**
		 * Returns the remaining hop count
		 * @return Value of remaining hop count
		 */
		uint8_t getRemainingHopCount() const
		{
			return getMstpHeader()->remainId;
		}

		/**
		 * Returns the remaining hop count
		 * @param[in] value Value of remaining hop count
		 */
		void setRemainingHopCount(uint8_t value)
		{
			getMstpHeader()->remainId = value;
		}

		/**
		 * Returns the total number of MSTI configuration messages
		 * @return Number of MSTI configuration messages. Can be between 0 and 64.
		 */
		uint8_t getNumberOfMSTIConfMessages() const
		{
			return (getVersion3Len() - (sizeof(mstp_conf_bpdu) - sizeof(rstp_conf_bpdu) - sizeof(uint16_t))) /
			       sizeof(msti_conf_msg);
		}

		/**
		 * Returns a reference to MSTI configuration messages. An MSTP packet can contain between 0 to 64 MSTI messages.
		 * The number of messages can be obtained by using getNumberOfMSTIConfMessages()
		 * @return An array pointer to MSTI configuration messages. Returns nullptr if there is no MSTI message.
		 */
		msti_conf_msg* getMstiConfMessages() const;

		// overridden methods

		/// Parses next layer
		void parseNextLayer()
		{}

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const
		{
			return "Multiple Spanning Tree";
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an Multiple STP packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an Spanning Tree packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen)
		{
			return data && dataLen >= sizeof(mstp_conf_bpdu);
		}
	};
}  // namespace vanhooks::net
// ---- end StpLayer.h ----

// ---- begin WakeOnLanLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * Class for representing the Wake on LAN Layer
	 */
	class WakeOnLanLayer : public Layer
	{
	private:
		void init(uint16_t len);

	public:
		/**
		 * @struct wol_header
		 * Wake On LAN protocol header
		 */
#pragma pack(push, 1)
		struct wol_header
		{
			/// Sync stream (FF FF FF FF FF FF)
			uint8_t sync[6];
			/// Target MAC address repeated 16 times
			uint8_t addrBody[6 * 16];
		};
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		WakeOnLanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, WakeOnLan)
		{}

		/**
		 * Construct a new Wake On Lan Layer with provided values
		 * @param[in] targetAddr Target MAC address
		 */
		explicit WakeOnLanLayer(const vanhooks::net::MacAddress& targetAddr);

		/**
		 * Construct a new Wake On Lan Layer with provided values
		 * @param[in] targetAddr Target MAC address
		 * @param[in] password Password as array
		 * @param[in] len Length of the password array, length of the password should be less than 6 bytes
		 */
		WakeOnLanLayer(const vanhooks::net::MacAddress& targetAddr, uint8_t* password, uint8_t len);

		/**
		 * Construct a new Wake On Lan Layer with provided values
		 * @param[in] targetAddr Target MAC address
		 * @param[in] password Password as MAC address
		 */
		WakeOnLanLayer(const vanhooks::net::MacAddress& targetAddr, const vanhooks::net::MacAddress& password);

		/**
		 * Construct a new Wake On Lan Layer with provided values
		 * @param[in] targetAddr Target MAC address
		 * @param[in] password Password as IPv4 address
		 */
		WakeOnLanLayer(const vanhooks::net::MacAddress& targetAddr, const IPv4Address& password);

		/**
		 * Get a pointer to the Wake On LAN header. Notice this points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the wol_header
		 */
		inline wol_header* getWakeOnLanHeader() const
		{
			return (wol_header*)m_Data;
		}

		/**
		 * Get the target MAC address of the command
		 * @return MAC address of the target
		 */
		vanhooks::net::MacAddress getTargetAddr() const;

		/**
		 * Set the target MAC address
		 * @param[in] targetAddr MAC address of the target
		 */
		void setTargetAddr(const vanhooks::net::MacAddress& targetAddr);

		/**
		 * Get the password of the command
		 * @return Returns the password if exists, empty string otherwise
		 */
		std::string getPassword() const;

		/**
		 * Set the password of the command
		 * @param[in] password Password as array
		 * @param[in] len Length of the password array, length of the password should be less than 6 bytes
		 * @return True if operation successful, false otherwise
		 */
		bool setPassword(const uint8_t* password, uint8_t len);

		/**
		 * Set the password of the command
		 * @param[in] password Password as string. Length of the password should be less than 6 bytes
		 * @return True if operation successful, false otherwise
		 */
		bool setPassword(const std::string& password);

		/**
		 * Set the password of the command
		 * @param[in] addr Password as MAC address
		 * @return True if operation successful, false otherwise
		 */
		bool setPassword(const MacAddress& addr);

		/**
		 * Set the password of the command
		 * @param addr Password as IPv4 address
		 * @return True if operation successful, false otherwise
		 */
		bool setPassword(const IPv4Address& addr);

		/**
		 * A static method that checks whether the port is considered as Wake on LAN
		 * @param[in] port The port number to be checked
		 */
		static bool isWakeOnLanPort(uint16_t port)
		{
			return (port == 0) || (port == 7) || (port == 9);
		}

		/**
		 * A static method that takes a byte array and detects whether it is a Wake on LAN message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as Wake on LAN message
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		// overridden methods

		/// Parses the next layer. Wake on LAN is the always last so does nothing for this layer
		void parseNextLayer()
		{}

		/**
		 * @return Get the size of the layer
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields()
		{}

		/**
		 * @return The OSI layer level of Wake on LAN (Data Link Layer)
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};
}  // namespace vanhooks::net
// ---- end WakeOnLanLayer.h ----

// ---- begin NullLoopbackLayer.h ----
/// @file


namespace vanhooks::net
{

/** IPv4 protocol **/
#define VH_BSD_AF_INET 2
/** XEROX NS protocols */
#define VH_BSD_AF_NS 6
/** ISO */
#define VH_BSD_AF_ISO 7
/** AppleTalk */
#define VH_BSD_AF_APPLETALK 16
/** IPX */
#define VH_BSD_AF_IPX 23
/** OpenBSD (and probably NetBSD), BSD/OS IPv6 */
#define VH_BSD_AF_INET6_BSD 24
/** FreeBSD IPv6 */
#define VH_BSD_AF_INET6_FREEBSD 28
/** Darwin IPv6 */
#define VH_BSD_AF_INET6_DARWIN 30

	/**
	 * @class NullLoopbackLayer
	 * Represents a Null/Loopback layer
	 */
	class NullLoopbackLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NullLoopbackLayer(uint8_t* data, size_t dataLen, Packet* packet)
		    : Layer(data, dataLen, nullptr, packet, NULL_LOOPBACK)
		{}

		/**
		 * A constructor that allocates a new Null/Loopback header
		 * @param[in] family The family protocol to set
		 */
		explicit NullLoopbackLayer(uint32_t family);

		/**
		 * A destructor for this layer (does nothing)
		 */
		~NullLoopbackLayer()
		{}

		/**
		 * @return The protocol family in this layer
		 */
		uint32_t getFamily() const;

		/**
		 * Set a protocol family
		 * @param[in] family The family protocol to set
		 */
		void setFamily(uint32_t family);

		// implement abstract methods

		/**
		 * Identifies the next layers by family:
		 * - for ::VH_BSD_AF_INET the next layer is IPv4Layer
		 * - for ::VH_BSD_AF_INET6_BSD, ::VH_BSD_AF_INET6_FREEBSD, ::VH_BSD_AF_INET6_DARWIN the next layer is
		 * IPv6Layer
		 * - for other values the next layer in PayloadLayer (unknown protocol)
		 */
		void parseNextLayer();

		/**
		 * @return Size of Null/Loopback header = 4B
		 */
		size_t getHeaderLen() const
		{
			return sizeof(uint32_t);
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
// ---- end NullLoopbackLayer.h ----

// ---- begin SllLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct sll_header
	 * Represents SLL header
	 */
#pragma pack(push, 1)
	struct sll_header
	{
		/** Specifies whether packet was: specifically sent to us by somebody else (value=0);
		 *  broadcast by somebody else (value=1); multicast, but not broadcast, by somebody else (value=2);
		 *  sent to somebody else by somebody else (value=3); sent by us (value=4)
		 **/
		uint16_t packet_type;
		/** Contains a Linux ARPHRD_ value for the link-layer device type */
		uint16_t ARPHRD_type;
		/** Contains the length of the link-layer address of the sender of the packet. That length could be zero */
		uint16_t link_layer_addr_len;
		/** contains the link-layer address of the sender of the packet; the number of bytes of that field that are
		 *  meaningful is specified by the link-layer address length field
		 **/
		uint8_t link_layer_addr[8];
		/** Contains an Ethernet protocol type of the next layer */
		uint16_t protocol_type;
	};
#pragma pack(pop)

	/**
	 * @class SllLayer
	 * Represents an SLL (Linux cooked capture) protocol layer
	 */
	class SllLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SllLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, SLL)
		{}

		/**
		 * A constructor that creates a new SLL header and allocates the data
		 * @param[in] packetType The packet type
		 * @param[in] ARPHRDType The ARPHRD type
		 */
		SllLayer(uint16_t packetType, uint16_t ARPHRDType);

		~SllLayer()
		{}

		/**
		 * Get a pointer to the Sll header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the sll_header
		 */
		sll_header* getSllHeader() const
		{
			return (sll_header*)m_Data;
		}

		/**
		 * A setter for the link layer address field
		 * @param[in] addr The address to set. Memory will be copied to packet
		 * @param[in] addrLength Address length, must be lower or equal to 8 (which is max length for SLL address)
		 * @return True if address was set successfully, or false of addrLength is out of bounds (0 or larger than 8)
		 */
		bool setLinkLayerAddr(uint8_t* addr, size_t addrLength);

		/**
		 * Set a MAC address in the link layer address field
		 * @param[in] macAddr MAC address to set
		 * @return True if address was set successfully, false if MAC address isn't valid or if set failed
		 */
		bool setMacAddressAsLinkLayer(const MacAddress& macAddr);

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer, PPPoESessionLayer,
		 * PPPoEDiscoveryLayer, MplsLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of sll_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(sll_header);
		}

		/**
		 * Calculate the next protocol type for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end SllLayer.h ----

// ---- begin Sll2Layer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @struct sll2_header
	 * Represents SLL2 header
	 */
#pragma pack(push, 1)
	struct sll2_header
	{
		/** Contains an Ethernet protocol type of the next layer */
		uint16_t protocol_type;
		/** The "Reserved (MBZ)" field is reserved, and must be set to zero */
		uint16_t reserved;
		/** The interface index field is a signed integer in network byte
		 * order and contains the 1-based index of the interface on which the packet was observed
		 **/
		uint32_t interface_index;
		/** Contains a Linux ARPHRD_ value for the link-layer device type */
		uint16_t ARPHRD_type;
		/** Specifies whether packet was: specifically sent to us by somebody else (value=0);
		 *  broadcast by somebody else (value=1); multicast, but not broadcast, by somebody else (value=2);
		 *  sent to somebody else by somebody else (value=3); sent by us (value=4)
		 **/
		uint8_t packet_type;
		/** Contains the length of the link-layer address of the sender of the packet. That length could be zero */
		uint8_t link_layer_addr_len;
		/** Contains the link-layer address of the sender of the packet; the number of bytes of that field that are
		 *  meaningful is specified by the link-layer address length field
		 **/
		uint8_t link_layer_addr[8];
	};
#pragma pack(pop)

	/**
	 * @class Sll2Layer
	 * Represents an SLL2 (Linux cooked capture) protocol layer
	 */
	class Sll2Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		Sll2Layer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, SLL2)
		{}

		/**
		 * A constructor that creates a new SLL2 header and allocates the data
		 * @param[in] interfaceIndex The interface index
		 * @param[in] ARPHRDType The ARPHRD type
		 * @param[in] packetType The packet type
		 */
		Sll2Layer(uint32_t interfaceIndex, uint16_t ARPHRDType, uint8_t packetType);

		~Sll2Layer()
		{}

		/**
		 * Get a pointer to the Sll header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the sll2_header
		 */
		sll2_header* getSll2Header() const
		{
			return (sll2_header*)m_Data;
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an IEEE 802.3 Eth packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an IEEE 802.3 Eth packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/**
		 * Get a protocol type of this layer
		 * @return protocol type
		 */
		uint16_t getProtocolType() const;

		/**
		 * Set protocol type of this layer
		 * @param[in] protocolType type to set
		 */
		void setProtocolType(uint16_t protocolType);

		/**
		 * Get interface index of this layer
		 * @return interface index
		 */
		uint32_t getInterfaceIndex() const;

		/**
		 * Set interface index of this layer
		 * @param[in] interfaceIndex interface index to set
		 */
		void setInterfaceIndex(uint32_t interfaceIndex);

		/**
		 * Get arphrd type of this layer
		 * @return arphrd type
		 */
		uint16_t getArphrdType() const;

		/**
		 * Set arphrd type of this layer
		 * @param[in] arphrdType arphrd type to set
		 */
		void setArphrdType(uint16_t arphrdType);

		/**
		 * Get packet type of this layer
		 * @return packet type
		 */
		uint8_t getPacketType() const;

		/**
		 * Set packet type of this layer
		 * @param[in] packetType packet type to set
		 */
		void setPacketType(uint8_t packetType);

		/**
		 * Get link layer address length
		 * @return link layer address length
		 */
		uint8_t getLinkLayerAddrLen() const;

		/**
		 * Get link layer address data pointer
		 * @return link layer address data pointer
		 */
		const uint8_t* getLinkLayerAddr() const;

		/**
		 * A setter for the link layer address field
		 * @param[in] addr The address to set. Memory will be copied to packet
		 * @param[in] addrLength Address length, must be lower or equal to 8 (which is max length for SLL2 address)
		 * @return True if address was set successfully, or false of addrLength is out of bounds (0 or larger than 8)
		 */
		bool setLinkLayerAddr(const uint8_t* addr, size_t addrLength);

		/**
		 * Get a MAC address in the link layer address field
		 * @return return macAddress pointer was set successfully, null pointer if d MAC address isn't valid or if set
		 * failed
		 */
		MacAddress getLinkLayerAsMacAddress();

		/**
		 * Set a MAC address in the link layer address field
		 * @param[in] macAddr MAC address to set
		 * @return True if address was set successfully, false if MAC address isn't valid or if set failed
		 */
		bool setMacAddressAsLinkLayer(const MacAddress& macAddr);

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer, PPPoESessionLayer,
		 * PPPoEDiscoveryLayer, MplsLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * Calculate the next protocol type for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		/**
		 * @return Size of sll2_header
		 */
		size_t getHeaderLen() const
		{
			return sizeof(sll2_header);
		}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end Sll2Layer.h ----

// ---- begin NflogLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @struct nflog_header
	 * Represents Nflog header
	 */
#pragma pack(push, 1)
	struct nflog_header
	{
		/** A Linux AF_ value, so it's 2 for IPv4 and 10 for IPv6 */
		uint8_t addressFamily;
		/** The version field is 0 for the current version of the pseudo-header */
		uint8_t version;
		/** The network byte order (big-endian) */
		uint16_t resourceId;
	};
#pragma pack(pop)

	/**
	 * @enum NflogTlvType
	 * Represents TLV types of NFLOG packets
	 */
	enum class NflogTlvType
	{
		/** the packet header structure */
		NFULA_PACKET_HDR = 1,
		/** packet mark from skbuff */
		NFULA_MARK = 2,
		/** nflog_timestamp_t for skbuff's time stamp */
		NFULA_TIMESTAMP = 3,
		/** ifindex of device on which packet received (possibly bridge group) */
		NFULA_IFINDEX_INDEV = 4,
		/** ifindex of device on which packet transmitted (possibly bridge group) */
		NFULA_IFINDEX_OUTDEV = 5,
		/** ifindex of physical device on which packet received (not bridge group) */
		NFULA_IFINDEX_PHYSINDEV = 6,
		/** ifindex of physical device on which packet transmitted (not bridge group) */
		NFULA_IFINDEX_PHYSOUTDEV = 7,
		/** nflog_hwaddr_t for hardware address */
		NFULA_HWADDR = 8,
		/** packet payload */
		NFULA_PAYLOAD = 9,
		/** text string - null-terminated, count includes NUL */
		NFULA_PREFIX = 10,
		/** UID owning socket on which packet was sent/received */
		NFULA_UID = 11,
		/** sequence number of packets on this NFLOG socket */
		NFULA_SEQ = 12,
		/** sequence number of packets on all NFLOG sockets */
		NFULA_SEQ_GLOBAL = 13,
		/** GID owning socket on which packet was sent/received */
		NFULA_GID = 14,
		/** ARPHRD_ type of skbuff's device */
		NFULA_HWTYPE = 15,
		/** skbuff's MAC-layer header */
		NFULA_HWHEADER = 16,
		/** length of skbuff's MAC-layer header */
		NFULA_HWLEN = 17,
	};

	/**
	 * @class NflogTlv
	 * A wrapper class for NFLOG TLV fields. This class does not create or modify TLVs related to NFLOG, but rather
	 * serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	 */
	class NflogTlv
	{
	private:
		struct NflogTLVRawData
		{
			/** Record length in bytes */
			uint16_t recordLen;
			/** Record type */
			uint16_t recordType;
			/** Record value (variable size) */
			uint8_t recordValue[];
		};
		NflogTLVRawData* m_Data;

	public:
		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] recordRawData A pointer to the option raw data
		 */
		explicit NflogTlv(uint8_t* recordRawData)
		{
			assign(recordRawData);
		}

		/**
		 * @return recordLen attribute in NflogTLVRawData
		 */
		size_t getTotalSize() const
		{
			// as in
			// https://github.com/the-tcpdump-group/libpcap/blob/766b607d60d8038087b49fc4cf433dac3dcdb49c/pcap-util.c#L371-L374
			return align<4>(m_Data->recordLen);
		}

		/**
		 * Assign a pointer to the TLV record raw data (byte array)
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 */
		void assign(uint8_t* recordRawData)
		{
			m_Data = (NflogTLVRawData*)recordRawData;
		}

		/**
		 * Check if a pointer can be assigned to the TLV record data
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 * @param[in] tlvDataLen The size of the TLV record raw data
		 * * @return True if data is valid and can be assigned
		 */
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			return recordRawData != nullptr && tlvDataLen >= sizeof(NflogTLVRawData::recordLen);
		}

		/**
		 * @return True if the TLV record raw data is nullptr, false otherwise
		 */
		bool isNull() const
		{
			return (m_Data == nullptr);
		}

		/**
		 * @return The type field of the record (the 'T' in __Type__-Length-Value)
		 */
		uint16_t getType() const
		{
			return m_Data->recordType;
		}

		/**
		 * @return A pointer to the TLV record raw data byte stream
		 */
		uint8_t* getRecordBasePtr() const
		{
			return (uint8_t*)m_Data;
		}

		/**
		 * @return A pointer to the value of the record as byte array (the 'V' in Type-Length- __Value__)
		 */
		uint8_t* getValue() const
		{
			return m_Data->recordValue;
		}
	};

	/**
	 * @class NflogLayer
	 * Represents an NFLOG protocol layer
	 */
	class NflogLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NflogLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, nullptr, packet, NFLOG)
		{}

		~NflogLayer()
		{}

		/**
		 * Get a pointer to the Nflog header.
		 * @return A pointer to the nflog_header
		 */
		nflog_header* getNflogHeader() const
		{
			return (nflog_header*)m_Data;
		}

		/**
		 * Get address family of the packet. e.g. 2 for ipv4 and 10 for ipv6
		 * @return an unsigned char of address family
		 */
		uint8_t getFamily();

		/**
		 * Get Version number inside packet header
		 * The version field is 0 for the current version of the pseudo-header
		 * @return an unsigned char for version
		 */
		uint8_t getVersion();

		/**
		 * Get Resource Id in packet header
		 * On one netlink socket it's possible to listen to several nflog groups; the resource ID is the nflog group for
		 * the packet
		 */
		uint16_t getResourceId();

		/**
		 * Get a TLV object found with the input type. if no tlv is found, the internal value of the object will set to
		 * nullptr
		 * @param[in] type type of tlv by using enum class defined as NflogTlvType
		 * @return NflogTlv obtained by type
		 */
		NflogTlv getTlvByType(NflogTlvType type) const;

		// implement abstract methods

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer using address family
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of nflog_header
		 */
		size_t getHeaderLen() const;

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {};

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an NFLOG packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an NFLOG packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);

	private:
		uint8_t* getTlvsBasePtr() const
		{
			return m_Data + sizeof(nflog_header);
		}

		TLVRecordReader<NflogTlv> m_TlvReader;
	};

}  // namespace vanhooks::net
// ---- end NflogLayer.h ----

// ---- begin PPPoELayer.h ----
#include <vector>
#include <string.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct pppoe_header
	 * Represents an PPPoE protocol header
	 */
#pragma pack(push, 1)
	struct pppoe_header
	{
#if (BYTE_ORDER == LITTLE_ENDIAN)
		/** PPPoE version */
		uint8_t version : 4;
		/** PPPoE type */
		uint8_t type : 4;
		/** PPPoE code */
		uint8_t code;
#else
		/** PPPoE version */
		uint16_t version : 4;
		/** PPPoE type */
		uint16_t type : 4;
		/** PPPoE code */
		uint16_t code : 8;
#endif
		/** PPPoE session ID (relevant for PPPoE session packets only) */
		uint16_t sessionId;
		/** Length (in bytes) of payload, not including the PPPoE header */
		uint16_t payloadLength;
	};
#pragma pack(pop)

	/**
	 * @class PPPoELayer
	 * An abstract class that describes the PPPoE protocol. Contains common data and logic of the two types of PPPoE
	 * packets: PPPoE session and PPPoE discovery
	 */
	class PPPoELayer : public Layer
	{
	public:
		/**
		 * PPPoE possible codes
		 */
		enum PPPoECode
		{
			/** PPPoE session code */
			PPPOE_CODE_SESSION = 0x00,
			/** PPPoE discovery PADO */
			PPPOE_CODE_PADO = 0x07,
			/** PPPoE discovery PADI */
			PPPOE_CODE_PADI = 0x09,
			/** PPPoE discovery PADG */
			PPPOE_CODE_PADG = 0x0a,
			/** PPPoE discovery PADC */
			PPPOE_CODE_PADC = 0x0b,
			/** PPPoE discovery PADQ */
			PPPOE_CODE_PADQ = 0x0c,
			/** PPPoE discovery PADR */
			PPPOE_CODE_PADR = 0x19,
			/** PPPoE discovery PADS */
			PPPOE_CODE_PADS = 0x65,
			/** PPPoE discovery PADT */
			PPPOE_CODE_PADT = 0xa7,
			/** PPPoE discovery PADM */
			PPPOE_CODE_PADM = 0xd3,
			/** PPPoE discovery PADN */
			PPPOE_CODE_PADN = 0xd4
		};

		~PPPoELayer()
		{}

		/**
		 * Get a pointer to the PPPoE header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the pppoe_header
		 */
		pppoe_header* getPPPoEHeader() const
		{
			return (pppoe_header*)m_Data;
		}

		// abstract methods implementation

		/**
		 * Calculate @ref pppoe_header#payloadLength field
		 */
		virtual void computeCalculateFields();

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelDataLinkLayer;
		}

	protected:
		// protected c'tor as this class shouldn't be instantiated
		PPPoELayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol)
		    : Layer(data, dataLen, prevLayer, packet, protocol)
		{}

		// protected c'tor as this class shouldn't be instantiated
		PPPoELayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId,
		           size_t additionalBytesToAllocate = 0);
	};

	/**
	 * @class PPPoESessionLayer
	 * Describes the PPPoE session protocol
	 */
	class PPPoESessionLayer : public PPPoELayer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref pppoe_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		PPPoESessionLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : PPPoELayer(data, dataLen, prevLayer, packet, PPPoESession)
		{}

		/**
		 * A constructor that allocates a new PPPoE Session header with version, type and session ID
		 * @param[in] version PPPoE version
		 * @param[in] type PPPoE type
		 * @param[in] sessionId PPPoE session ID
		 * @param[in] pppNextProtocol The next protocol to come after the PPPoE session header. Should be one of the
		 * PPP_* macros listed below
		 */
		PPPoESessionLayer(uint8_t version, uint8_t type, uint16_t sessionId, uint16_t pppNextProtocol)
		    : PPPoELayer(version, type, PPPoELayer::PPPOE_CODE_SESSION, sessionId, sizeof(uint16_t))
		{
			setPPPNextProtocol(pppNextProtocol);
		}

		virtual ~PPPoESessionLayer()
		{}

		/**
		 * @return The protocol after the PPPoE session header. The return value is one of the PPP_* macros listed
		 * below. This method is also used when parsing a packet (this way we know which layer comes after the PPPoE
		 * session)
		 */
		uint16_t getPPPNextProtocol() const;

		/**
		 * Set the field that describes which header comes after the PPPoE session header
		 * @param[in] nextProtocol The protocol value. Should be one of the PPP_* macros listed below
		 */
		void setPPPNextProtocol(uint16_t nextProtocol);

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of byte stream of a packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent a PPPoES packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// abstract methods implementation

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer. Otherwise sets PayloadLayer
		 */
		virtual void parseNextLayer();

		/**
		 * @return Size of @ref pppoe_header
		 */
		virtual size_t getHeaderLen() const
		{
			return sizeof(pppoe_header) + sizeof(uint16_t);
		}

		virtual std::string toString() const;
	};

	/**
	 * @class PPPoEDiscoveryLayer
	 * Describes the PPPoE discovery protocol
	 */
	class PPPoEDiscoveryLayer : public PPPoELayer
	{
	public:
		/**
		 * PPPoE tag types
		 */
		enum PPPoETagTypes
		{
			/** End-Of-List tag type*/
			PPPOE_TAG_EOL = 0x0000,
			/** Service-Name tag type*/
			PPPOE_TAG_SVC_NAME = 0x0101,
			/** AC-Name tag type*/
			PPPOE_TAG_AC_NAME = 0x0102,
			/** Host-Uniq tag type*/
			PPPOE_TAG_HOST_UNIQ = 0x0103,
			/** AC-Cookie tag type*/
			PPPOE_TAG_AC_COOKIE = 0x0104,
			/** Vendor-Specific tag type*/
			PPPOE_TAG_VENDOR = 0x0105,
			/** Credits tag type*/
			PPPOE_TAG_CREDITS = 0x0106,
			/** Metrics tag type*/
			PPPOE_TAG_METRICS = 0x0107,
			/** Sequence Number tag type */
			PPPOE_TAG_SEQ_NUM = 0x0108,
			/** Credit Scale Factor tag type */
			PPPOE_TAG_CRED_SCALE = 0x0109,
			/** Relay-Session-Id tag type */
			PPPOE_TAG_RELAY_ID = 0x0110,
			/** HURL tag type */
			PPPOE_TAG_HURL = 0x0111,
			/** MOTM tag type */
			PPPOE_TAG_MOTM = 0x0112,
			/** PPP-Max-Payload tag type */
			PPPOE_TAG_MAX_PAYLD = 0x0120,
			/** IP_Route_Add tag type */
			PPPOE_TAG_IP_RT_ADD = 0x0121,
			/** Service-Name-Error tag type */
			PPPOE_TAG_SVC_ERR = 0x0201,
			/** AC-System-Error tag type */
			PPPOE_TAG_AC_ERR = 0x0202,
			/** Generic-Error tag type */
			PPPOE_TAG_GENERIC_ERR = 0x0203
		};

		/**
		 * @class PPPoETag
		 * Represents a PPPoE tag and its data
		 */
		class PPPoETag : public TLVRecord<uint16_t, uint16_t>
		{
		public:
			/**
			 * A c'tor that gets a pointer to the tag raw data (byte array)
			 * @param[in] tagRawData A pointer to the tag raw data
			 */
			explicit PPPoETag(uint8_t* tagRawData) : TLVRecord(tagRawData)
			{}

			/**
			 * A d'tor for this class, currently does nothing
			 */
			virtual ~PPPoETag()
			{}

			/**
			 * @return The tag type converted to PPPoEDiscoveryLayer#PPPoETagTypes enum
			 */
			PPPoEDiscoveryLayer::PPPoETagTypes getType() const;

			/**
			 * Retrieve the tag data as string. Relevant only if the tag value is indeed a string
			 * @return The tag data as string
			 */
			std::string getValueAsString() const
			{
				size_t dataSize = getDataSize();
				if (dataSize < 1)
					return "";

				return std::string((const char*)m_Data->recordValue, dataSize);
			}

			// implement abstract methods

			size_t getTotalSize() const;

			size_t getDataSize() const;
		};

		/**
		 * @class PPPoETagBuilder
		 * A class for building PPPoE Tags. This builder receives the tag parameters in its c'tor,
		 * builds the PPPoE Tag raw buffer and provides a build() method to get a PPPoETag object out of it
		 */
		class PPPoETagBuilder : public TLVRecordBuilder
		{
		public:
			/**
			 * A c'tor for building a PPPoE Tag which has no value (tag len is zero). The PPPoETag object can later
			 * be retrieved by calling build()
			 * @param[in] tagType Tag type
			 */
			explicit PPPoETagBuilder(PPPoETagTypes tagType)
			    : TLVRecordBuilder(static_cast<uint16_t>(tagType), nullptr, 0)
			{}

			/**
			 * A c'tor for building a PPPoE Tag which has a 4-byte value. The PPPoETag object can later
			 * be retrieved by calling build()
			 * @param[in] tagType Tag type
			 * @param[in] tagValue The tag's 4-byte value
			 */
			PPPoETagBuilder(PPPoETagTypes tagType, uint32_t tagValue)
			    : TLVRecordBuilder(static_cast<uint16_t>(tagType), tagValue)
			{}

			/**
			 * A c'tor for building a PPPoE Tag which has some arbitrary value. The PPPoETag object can later
			 * be retrieved by calling build()
			 * @param[in] tagType Tag type
			 * @param[in] tagValue A byte array that contains the tag data
			 * @param[in] tagValueLen The length of the value byte array
			 */
			PPPoETagBuilder(PPPoETagTypes tagType, uint8_t* tagValue, uint8_t tagValueLen)
			    : TLVRecordBuilder(static_cast<uint16_t>(tagType), tagValue, tagValueLen)
			{}

			/**
			 * Build the PPPoETag object out of the parameters defined in the c'tor
			 * @return The PPPoETag object
			 */
			PPPoETag build() const;
		};

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref pppoe_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		PPPoEDiscoveryLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : PPPoELayer(data, dataLen, prevLayer, packet, PPPoEDiscovery)
		{
			m_DataLen = getHeaderLen();
		}

		/**
		 * A constructor that allocates a new PPPoE Discovery header with version, type, PPPoE code and session ID
		 * @param[in] version PPPoE version
		 * @param[in] type PPPoE type
		 * @param[in] code PPPoE code enum
		 * @param[in] sessionId PPPoE session ID
		 */
		PPPoEDiscoveryLayer(uint8_t version, uint8_t type, PPPoELayer::PPPoECode code, uint16_t sessionId)
		    : PPPoELayer(version, type, code, sessionId)
		{
			m_Protocol = PPPoEDiscovery;
		}

		/**
		 * Get a PPPoE Tag by tag type.
		 * @param[in] tagType The type of the tag to search
		 * @return A PPPoETag object that contains the first tag that matches this type, or logical null
		 * (PPPoETag#isNull() == true) if no such tag found
		 */
		PPPoETag getTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType) const;

		/**
		 * @return The first tag in the PPPoE discovery layer. If the current layer contains no tags the returned value
		 * will contain a logical null (PPPoETag#isNull() == true)
		 */
		PPPoETag getFirstTag() const;

		/**
		 * Get the tag that comes right after the "tag" parameter. If the given tag is the last one, the returned value
		 * will contain a logical null (PPPoETag#isNull() == true)
		 * @param[in] tag A given tag
		 * @return A PPPoETag object containing the tag that comes next, or logical null if the given
		 * tag: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		 */
		PPPoETag getNextTag(const PPPoETag& tag) const;

		/**
		 * @return The number of tags in this layer
		 */
		int getTagCount() const;

		/**
		 * Add a new PPPoE Tag at the end of the layer
		 * @param[in] tagBuilder A PPPoETagBuilder object that contains the requested tag data to add
		 * @return A PPPoETag object containing the newly added PPPoE Tag data or logical null
		 * (PPPoETag#isNull() == true) if addition failed
		 */
		PPPoETag addTag(const PPPoETagBuilder& tagBuilder);

		/**
		 * Add a new PPPoE Tag after an existing one
		 * @param[in] tagBuilder A PPPoETagBuilder object that contains the requested tag data to add
		 * @param[in] prevTagType The PPPoE Tag which the newly added tag will come after
		 * @return A PPPoETag object containing the newly added PPPoE Tag data or logical null
		 * (PPPoETag#isNull() == true) if addition failed
		 */
		PPPoETag addTagAfter(const PPPoETagBuilder& tagBuilder, PPPoETagTypes prevTagType);

		/**
		 * Remove an existing tag. Tag will be found by the tag type
		 * @param[in] tagType The tag type to remove
		 * @return True if tag was removed or false if tag wasn't found or if tag removal failed (in each case a proper
		 * error will be written to log)
		 */
		bool removeTag(PPPoEDiscoveryLayer::PPPoETagTypes tagType);

		/**
		 * Remove all tags in this layer
		 * @return True if all tags were successfully or false if removal failed for some reason (a proper error will be
		 * written to log)
		 */
		bool removeAllTags();

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of byte stream of a packet
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent a PPPoED packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// abstract methods implementation

		/**
		 * Does nothing for this layer (PPPoE discovery is always the last layer)
		 */
		virtual void parseNextLayer()
		{}

		/**
		 * @return The header length which is size of strcut pppoe_header plus the total size of tags
		 */
		virtual size_t getHeaderLen() const;

		virtual std::string toString() const
		{
			return "PPP-over-Ethernet Discovery (" + codeToString((PPPoELayer::PPPoECode)getPPPoEHeader()->code) + ")";
		}

	private:
		TLVRecordReader<PPPoETag> m_TagReader;

		PPPoETag addTagAt(const PPPoETagBuilder& tagBuilder, int offset);

		uint8_t* getTagBasePtr() const
		{
			return m_Data + sizeof(pppoe_header);
		}

		std::string codeToString(PPPoECode code) const;
	};

	// implementation of inline methods

	bool PPPoESessionLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(pppoe_header) + sizeof(uint16_t);
	}

	bool PPPoEDiscoveryLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(pppoe_header);
	}

	// Copied from Wireshark: ppptypes.h

	/** Padding Protocol */
#define VH_PPP_PADDING 0x1
	/** ROHC small-CID */
#define VH_PPP_ROHC_SCID 0x3
	/** ROHC large-CID */
#define VH_PPP_ROHC_LCID 0x5
	/** Internet Protocol version 4 */
#define VH_PPP_IP 0x21
	/** OSI Network Layer */
#define VH_PPP_OSI 0x23
	/** Xerox NS IDP */
#define VH_PPP_XNSIDP 0x25
	/** DECnet Phase IV */
#define VH_PPP_DEC4 0x27
	/** AppleTalk */
#define VH_PPP_AT 0x29
	/** Novell IPX */
#define VH_PPP_IPX 0x2b
	/** Van Jacobson Compressed TCP/IP */
#define VH_PPP_VJC_COMP 0x2d
	/** Van Jacobson Uncompressed TCP/IP */
#define VH_PPP_VJC_UNCOMP 0x2f
	/** Bridging PDU */
#define VH_PPP_BCP 0x31
	/** Stream Protocol (ST-II) */
#define VH_PPP_ST 0x33
	/** Banyan Vines */
#define VH_PPP_VINES 0x35
	/** AppleTalk EDDP */
#define VH_PPP_AT_EDDP 0x39
	/** AppleTalk SmartBuffered */
#define VH_PPP_AT_SB 0x3b
	/** Multi-Link */
#define VH_PPP_MP 0x3d
	/** NETBIOS Framing */
#define VH_PPP_NB 0x3f
	/** Cisco Systems */
#define VH_PPP_CISCO 0x41
	/** Ascom Timeplex */
#define VH_PPP_ASCOM 0x43
	/** Fujitsu Link Backup and Load Balancing */
#define VH_PPP_LBLB 0x45
	/** DCA Remote Lan */
#define VH_PPP_RL 0x47
	/** Serial Data Transport Protocol */
#define VH_PPP_SDTP 0x49
	/** SNA over 802.2 */
#define VH_PPP_LLC 0x4b
	/** SNA */
#define VH_PPP_SNA 0x4d
	/** IPv6 Header Compression  */
#define VH_PPP_IPV6HC 0x4f
	/** KNX Bridging Data */
#define VH_PPP_KNX 0x51
	/** Encryption */
#define VH_PPP_ENCRYPT 0x53
	/** Individual Link Encryption */
#define VH_PPP_ILE 0x55
	/** Internet Protocol version 6 */
#define VH_PPP_IPV6 0x57
	/** PPP Muxing */
#define VH_PPP_MUX 0x59
	/** Vendor-Specific Network Protocol (VSNP) */
#define VH_PPP_VSNP 0x5b
	/** TRILL Network Protocol (TNP) */
#define VH_PPP_TNP 0x5d
	/** RTP IPHC Full Header */
#define VH_PPP_RTP_FH 0x61
	/** RTP IPHC Compressed TCP */
#define VH_PPP_RTP_CTCP 0x63
	/** RTP IPHC Compressed Non TCP */
#define VH_PPP_RTP_CNTCP 0x65
	/** RTP IPHC Compressed UDP 8 */
#define VH_PPP_RTP_CUDP8 0x67
	/** RTP IPHC Compressed RTP 8 */
#define VH_PPP_RTP_CRTP8 0x69
	/** Stampede Bridging */
#define VH_PPP_STAMPEDE 0x6f
	/** MP+ Protocol */
#define VH_PPP_MPPLUS 0x73
	/** NTCITS IPI */
#define VH_PPP_NTCITS_IPI 0xc1
	/** Single link compression in multilink */
#define VH_PPP_ML_SLCOMP 0xfb
	/** Compressed datagram */
#define VH_PPP_COMP 0xfd
	/** 802.1d Hello Packets */
#define VH_PPP_STP_HELLO 0x0201
	/** IBM Source Routing BPDU */
#define VH_PPP_IBM_SR 0x0203
	/** DEC LANBridge100 Spanning Tree */
#define VH_PPP_DEC_LB 0x0205
	/** Cisco Discovery Protocol */
#define VH_PPP_CDP 0x0207
	/** Netcs Twin Routing */
#define VH_PPP_NETCS 0x0209
	/** STP - Scheduled Transfer Protocol */
#define VH_PPP_STP 0x020b
	/** EDP - Extreme Discovery Protocol */
#define VH_PPP_EDP 0x020d
	/** Optical Supervisory Channel Protocol */
#define VH_PPP_OSCP 0x0211
	/** Optical Supervisory Channel Protocol */
#define VH_PPP_OSCP2 0x0213
	/** Luxcom */
#define VH_PPP_LUXCOM 0x0231
	/** Sigma Network Systems */
#define VH_PPP_SIGMA 0x0233
	/** Apple Client Server Protocol */
#define VH_PPP_ACSP 0x0235
	/** MPLS Unicast */
#define VH_PPP_MPLS_UNI 0x0281
	/** MPLS Multicast */
#define VH_PPP_MPLS_MULTI 0x0283
	/** IEEE p1284.4 standard - data packets */
#define VH_PPP_P12844 0x0285
	/** ETSI TETRA Network Protocol Type 1 */
#define VH_PPP_TETRA 0x0287
	/** Multichannel Flow Treatment Protocol */
#define VH_PPP_MFTP 0x0289
	/** RTP IPHC Compressed TCP No Delta */
#define VH_PPP_RTP_CTCPND 0x2063
	/** RTP IPHC Context State */
#define VH_PPP_RTP_CS 0x2065
	/** RTP IPHC Compressed UDP 16 */
#define VH_PPP_RTP_CUDP16 0x2067
	/** RTP IPHC Compressed RTP 16 */
#define VH_PPP_RTP_CRDP16 0x2069
	/** Cray Communications Control Protocol */
#define VH_PPP_CCCP 0x4001
	/** CDPD Mobile Network Registration Protocol */
#define VH_PPP_CDPD_MNRP 0x4003
	/** Expand accelerator protocol */
#define VH_PPP_EXPANDAP 0x4005
	/** ODSICP NCP */
#define VH_PPP_ODSICP 0x4007
	/** DOCSIS DLL */
#define VH_PPP_DOCSIS 0x4009
	/** Cetacean Network Detection Protocol */
#define VH_PPP_CETACEANNDP 0x400b
	/** Stacker LZS */
#define VH_PPP_LZS 0x4021
	/** RefTek Protocol */
#define VH_PPP_REFTEK 0x4023
	/** Fibre Channel */
#define VH_PPP_FC 0x4025
	/** EMIT Protocols */
#define VH_PPP_EMIT 0x4027
	/** Vendor-Specific Protocol (VSP) */
#define VH_PPP_VSP 0x405b
	/** TRILL Link State Protocol (TLSP) */
#define VH_PPP_TLSP 0x405d
	/** Internet Protocol Control Protocol */
#define VH_PPP_IPCP 0x8021
	/** OSI Network Layer Control Protocol */
#define VH_PPP_OSINLCP 0x8023
	/** Xerox NS IDP Control Protocol */
#define VH_PPP_XNSIDPCP 0x8025
	/** DECnet Phase IV Control Protocol */
#define VH_PPP_DECNETCP 0x8027
	/** AppleTalk Control Protocol */
#define VH_PPP_ATCP 0x8029
	/** Novell IPX Control Protocol */
#define VH_PPP_IPXCP 0x802b
	/** Bridging NCP */
#define VH_PPP_BRIDGENCP 0x8031
	/** Stream Protocol Control Protocol */
#define VH_PPP_SPCP 0x8033
	/** Banyan Vines Control Protocol */
#define VH_PPP_BVCP 0x8035
	/** Multi-Link Control Protocol */
#define VH_PPP_MLCP 0x803d
	/** NETBIOS Framing Control Protocol */
#define VH_PPP_NBCP 0x803f
	/** Cisco Systems Control Protocol */
#define VH_PPP_CISCOCP 0x8041
	/** Ascom Timeplex Control Protocol (?) */
#define VH_PPP_ASCOMCP 0x8043
	/** Fujitsu LBLB Control Protocol */
#define VH_PPP_LBLBCP 0x8045
	/** DCA Remote Lan Network Control Protocol */
#define VH_PPP_RLNCP 0x8047
	/** Serial Data Control Protocol */
#define VH_PPP_SDCP 0x8049
	/** SNA over 802.2 Control Protocol */
#define VH_PPP_LLCCP 0x804b
	/** SNA Control Protocol */
#define VH_PPP_SNACP 0x804d
	/** IP6 Header Compression Control Protocol */
#define VH_PPP_IP6HCCP 0x804f
	/** KNX Bridging Control Protocol */
#define VH_PPP_KNXCP 0x8051
	/** Encryption Control Protocol */
#define VH_PPP_ECP 0x8053
	/** Individual Link Encryption Control Protocol */
#define VH_PPP_ILECP 0x8055
	/** IPv6 Control Protocol */
#define VH_PPP_IPV6CP 0x8057
	/** PPP Muxing Control Protocol */
#define VH_PPP_MUXCP 0x8059
	/** Vendor-Specific Network Control Protocol (VSNCP)   [RFC3772] */
#define VH_PPP_VSNCP 0x805b
	/** TRILL Network Control Protocol (TNCP) */
#define VH_PPP_TNCP 0x805d
	/** Stampede Bridging Control Protocol */
#define VH_PPP_STAMPEDECP 0x806f
	/** MP+ Contorol Protocol */
#define VH_PPP_MPPCP 0x8073
	/** NTCITS IPI Control Protocol */
#define VH_PPP_IPICP 0x80c1
	/** Single link compression in multilink control */
#define VH_PPP_SLCC 0x80fb
	/** Compression Control Protocol */
#define VH_PPP_CCP 0x80fd
	/** Cisco Discovery Protocol Control Protocol */
#define VH_PPP_CDPCP 0x8207
	/** Netcs Twin Routing */
#define VH_PPP_NETCSCP 0x8209
	/** STP - Control Protocol */
#define VH_PPP_STPCP 0x820b
	/** EDPCP - Extreme Discovery Protocol Control Protocol */
#define VH_PPP_EDPCP 0x820d
	/** Apple Client Server Protocol Control */
#define VH_PPP_ACSPC 0x8235
	/** MPLS Control Protocol */
#define VH_PPP_MPLSCP 0x8281
	/** IEEE p1284.4 standard - Protocol Control */
#define VH_PPP_P12844CP 0x8285
	/** ETSI TETRA TNP1 Control Protocol */
#define VH_PPP_TETRACP 0x8287
	/** Multichannel Flow Treatment Protocol */
#define VH_PPP_MFTPCP 0x8289
	/** Link Control Protocol */
#define VH_PPP_LCP 0xc021
	/** Password Authentication Protocol */
#define VH_PPP_PAP 0xc023
	/** Link Quality Report */
#define VH_PPP_LQR 0xc025
	/** Shiva Password Authentication Protocol */
#define VH_PPP_SPAP 0xc027
	/** CallBack Control Protocol (CBCP) */
#define VH_PPP_CBCP 0xc029
	/** BACP Bandwidth Allocation Control Protocol */
#define VH_PPP_BACP 0xc02b
	/** BAP Bandwidth Allocation Protocol */
#define VH_PPP_BAP 0xc02d
	/** Vendor-Specific Authentication Protocol (VSAP) */
#define VH_PPP_VSAP 0xc05b
	/** Container Control Protocol */
#define VH_PPP_CONTCP 0xc081
	/** Challenge Handshake Authentication Protocol */
#define VH_PPP_CHAP 0xc223
	/** RSA Authentication Protocol */
#define VH_PPP_RSAAP 0xc225
	/** Extensible Authentication Protocol */
#define VH_PPP_EAP 0xc227
	/** Mitsubishi Security Information Exchange Protocol (SIEP) */
#define VH_PPP_SIEP 0xc229
	/** Stampede Bridging Authorization Protocol */
#define VH_PPP_SBAP 0xc26f
	/** Proprietary Authentication Protocol */
#define VH_PPP_PRPAP 0xc281
	/** Proprietary Authentication Protocol */
#define VH_PPP_PRPAP2 0xc283
	/** Proprietary Node ID Authentication Protocol */
#define VH_PPP_PRPNIAP 0xc481

}  // namespace vanhooks::net
// ---- end PPPoELayer.h ----

// ---- begin NdpLayer.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * An enum representing the available option types for Neighbor Discovery in IPv6 (see RFC 4861)
	 */
	enum class NDPNeighborOptionTypes : int
	{
		NDP_OPTION_SOURCE_LINK_LAYER = 1,
		NDP_OPTION_TARGET_LINK_LAYER = 2,
		NDP_OPTION_PREFIX_INFORMATION = 3,
		NDP_OPTION_REDIRECTED_HEADER = 4,
		NDP_OPTION_MTU = 5,
		NDP_OPTION_UNKNOWN = 255
	};

	/**
	 * @class NdpOption
	 * A wrapper class for NDP options. This class does not create or modify NDP option records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class NdpOption : public TLVRecord<uint8_t, uint8_t>
	{
	public:
		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the NDP option raw data
		 */
		explicit NdpOption(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		~NdpOption()
		{}

		/**
		 * @return NDP option type casted as vanhooks::net::NDPNeighborOptionTypes enum. If the data is null a value
		 * of NDP_OPTION_UNKNOWN is returned
		 */
		NDPNeighborOptionTypes getNdpOptionType() const
		{
			if (m_Data == nullptr)
				return NDPNeighborOptionTypes::NDP_OPTION_UNKNOWN;

			return static_cast<NDPNeighborOptionTypes>(m_Data->recordType);
		}

		// implement abstract methods

		size_t getTotalSize() const
		{
			if (m_Data == nullptr)
				return (size_t)0;

			return (size_t)m_Data->recordLen * 8;
		}

		size_t getDataSize() const
		{
			if (m_Data == nullptr)
			{
				return 0;
			}

			// length value is stored in units of 8 octets
			return (size_t)m_Data->recordLen * 8 - (2 * sizeof(uint8_t));
		}
	};

	/**
	 * @class NdpOptionBuilder
	 * A class for building NDP option records. This builder receives the NDP option parameters in its c'tor,
	 * builds the NDP option raw buffer and provides a build() method to get a NdpOption object out of it
	 */
	class NdpOptionBuilder : public TLVRecordBuilder
	{
	public:
		/**
		 * A c'tor for building NDP options which their value is a byte array. The NdpOption object can be later
		 * retrieved by calling build(). Each option is padded to have a 64-bit boundary.
		 * @param[in] optionType NDP option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		 * any way.
		 * @param[in] optionValueLen Option value length in bytes
		 */
		NdpOptionBuilder(NDPNeighborOptionTypes optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen)
		{}

		/**
		 * Build the NdpOption object out of the parameters defined in the c'tor. Padding bytes are added to the
		 * option for option length with 64-bit boundaries.
		 * @return The NdpOption object
		 */
		NdpOption build() const;
	};

	/**
	 * @class NDPLayerBase
	 * Represents a base for NDP packet types
	 */
	class NDPLayerBase : public IcmpV6Layer
	{
	public:
		virtual ~NDPLayerBase()
		{}

		/**
		 * @return The number of NDP options in this layer
		 */
		size_t getNdpOptionCount() const;

		/**
		 * Get a NDP option by type.
		 * @param[in] option NDP option type
		 * @return An NdpOption object that contains the first option that matches this type, or logical null
		 * (NdpOption#isNull() == true) if no such option found
		 */
		NdpOption getNdpOption(NDPNeighborOptionTypes option) const;

		/**
		 * @return The first NDP option in the packet. If the current layer contains no options the returned value will
		 * contain a logical null (NdpOption#isNull() == true)
		 */
		NdpOption getFirstNdpOption() const;

		/**
		 * Get the NDP option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical null (IdpOption#isNull() == true)
		 * @param[in] option An NDP option object that exists in the current layer
		 * @return A NdpOption object that contains the NDP option data that comes next, or logical null if the given
		 * NDP option: (1) was the last one; or (2) contains a logical null; or (3) doesn't belong to this packet
		 */
		NdpOption getNextNdpOption(NdpOption& option) const;

		/**
		 * Add a new NDP option at the end of the layer (after the last NDP option)
		 * @param[in] optionBuilder An NdpOptionBuilder object that contains the NDP option data to be added
		 * @return A NdpOption object that contains the newly added NDP option data or logical null
		 * (NdpOption#isNull() == true) if addition failed. In case of a failure a corresponding error message will be
		 * printed to log
		 */
		NdpOption addNdpOption(const NdpOptionBuilder& optionBuilder);

		/**
		 * Remove all NDP options from the layer
		 * @return True if options removed successfully or false if some error occurred (an appropriate error message
		 * will be printed to log)
		 */
		bool removeAllNdpOptions();

	protected:
		NDPLayerBase() = default;

		NDPLayerBase(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : IcmpV6Layer(data, dataLen, prevLayer, packet)
		{}

	private:
		TLVRecordReader<NdpOption> m_OptionReader;

		virtual size_t getNdpHeaderLen() const = 0;
		virtual uint8_t* getNdpOptionsBasePtr() const
		{
			return m_Data + getNdpHeaderLen();
		};
		NdpOption addNdpOptionAt(const NdpOptionBuilder& optionBuilder, int offset);
	};

	/**
	 * @class NDPNeighborSolicitationLayer
	 * Represents a NDP Neighbor Solicitation protocol layer
	 */
	class NDPNeighborSolicitationLayer : public NDPLayerBase
	{
	public:
		/**
		 * @struct ndpneighborsolicitationhdr
		 * Represents neighbor solicitation message format
		 */
#pragma pack(push, 1)
		struct ndpneighborsolicitationhdr : icmpv6hdr
		{
			/** Reserved */
			uint32_t reserved;
			/** Target address - Target address of solicitation message */
			uint8_t targetIP[16];
		};
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NDPNeighborSolicitationLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : NDPLayerBase(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor for a new NDPNeighborSolicitationLayer object
		 * @param[in] code Code field
		 * @param[in] targetIP Target IP address for which the solicitation shall be created
		 */
		NDPNeighborSolicitationLayer(uint8_t code, const IPv6Address& targetIP);

		/**
		 * A constructor for a new NDPNeighborSolicitationLayer object
		 * @param[in] code Code field
		 * @param[in] targetIP Target IP address for which the solicitation shall be created
		 * @param[in] srcMac Mac address which shall be put in the linklayer option
		 */
		NDPNeighborSolicitationLayer(uint8_t code, const IPv6Address& targetIP, const MacAddress& srcMac);

		virtual ~NDPNeighborSolicitationLayer()
		{}

		/**
		 * @return Get the IP address specified as the target IP address in the solicitation message
		 */
		IPv6Address getTargetIP() const
		{
			return IPv6Address(getNdpHeader()->targetIP);
		};

		/**
		 * Checks if the layer has a link layer address option set
		 * @return true if link layer address option is available, false otherwise
		 */
		bool hasLinkLayerAddress() const;

		/**
		 * Get the Link Layer Address
		 * @return Mac address which is specified in the link layer address option
		 */
		MacAddress getLinkLayerAddress() const;

		std::string toString() const;

	private:
		void initLayer(uint8_t code, const IPv6Address& targetIP);
		ndpneighborsolicitationhdr* getNdpHeader() const
		{
			return (ndpneighborsolicitationhdr*)m_Data;
		}
		size_t getNdpHeaderLen() const
		{
			return sizeof(ndpneighborsolicitationhdr);
		};
	};

	/**
	 * @class NDPNeighborAdvertisementLayer
	 * Represents a NDP Neighbor Advertisement protocol layer
	 */
	class NDPNeighborAdvertisementLayer : public NDPLayerBase
	{
	public:
		/**
		 * @struct ndpneighboradvertisementhdr
		 * Represents neighbor advertisement message format
		 */
#pragma pack(push, 1)
		struct ndpneighboradvertisementhdr : icmpv6hdr
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint32_t
			    /** Unused field */
			    reserved : 5,
			    /** Flag indicating that this entry should override the old one */
			    override : 1,
			    /** Flag indicating that the advertisement was sent in response to a Neighbor Solicitation from the
			    Destination address */
			    solicited : 1,
			    /** Flag indicating that the advertisement is sent by a router */
			    router : 1,
			    /** Unused field */
			    reserved2 : 24;
#else
			uint32_t
			    /** Flag indicating that the advertisement is sent by a router */
			    router : 1,
			    /** Flag indicating that the advertisement was sent in response to a Neighbor Solicitation from the
			       Destination address */
			    solicited : 1,
			    /** Flag indicating that this entry should override the old one */
			    override : 1,
			    /** Unused field */
			    reserved : 29;
#endif
			/** Target address - Either source address of advertisement or address for requested MAC */
			uint8_t targetIP[16];
		};
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NDPNeighborAdvertisementLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : NDPLayerBase(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor that allocates a new NDP Advertisement Layer with target link-layer address option
		 * @param[in] code Code field
		 * @param[in] targetIP The target IP address from the Neighbor Solicitation message (solicited advertisements)
		 * or the address whose link-layer address has changed (unsolicited advertisement)
		 * @param[in] targetMac Adds the target link-layer address into the option field of the layer
		 * @param[in] routerFlag The router flag
		 * @param[in] unicastFlag The solicited flag
		 * @param[in] overrideFlag The override flag
		 */
		NDPNeighborAdvertisementLayer(uint8_t code, const IPv6Address& targetIP, const MacAddress& targetMac,
		                              bool routerFlag, bool unicastFlag, bool overrideFlag);

		/**
		 * A constructor that allocates a new NDP Advertisement Layer
		 * @param code Code field
		 * @param targetIP The target IP address from the Neighbor Solicitation message (solicited advertisements) or
		 * the address whose link-layer address has changed (unsolicited advertisement)
		 * @param routerFlag The router flag
		 * @param unicastFlag The solicited flag
		 * @param overrideFlag The override flag
		 */
		NDPNeighborAdvertisementLayer(uint8_t code, const IPv6Address& targetIP, bool routerFlag, bool unicastFlag,
		                              bool overrideFlag);

		virtual ~NDPNeighborAdvertisementLayer()
		{}

		/**
		 * @return Get the target MAC address
		 */
		MacAddress getTargetMac() const;

		/**
		 * @return Get the target IP address
		 */
		IPv6Address getTargetIP() const
		{
			return IPv6Address(getNdpHeader()->targetIP);
		}

		/**
		 * @return Get information if the target link-layer address was added in the option field of the header
		 */
		bool hasTargetMacInfo() const;

		/**
		 * @return Get the router flag
		 */
		bool getRouterFlag() const
		{
			return getNdpHeader()->router;
		}

		/**
		 * @return Get the unicast flag
		 */
		bool getUnicastFlag() const
		{
			return getNdpHeader()->solicited;
		}

		/**
		 * @return Get the override flag
		 */
		bool getOverrideFlag() const
		{
			return getNdpHeader()->override;
		}

		std::string toString() const;

	private:
		void initLayer(uint8_t code, const IPv6Address& targetIP, bool routerFlag, bool unicastFlag, bool overrideFlag);
		ndpneighboradvertisementhdr* getNdpHeader() const
		{
			return (ndpneighboradvertisementhdr*)m_Data;
		}
		size_t getNdpHeaderLen() const
		{
			return sizeof(ndpneighboradvertisementhdr);
		};
	};

}  // namespace vanhooks::net
// ---- end NdpLayer.h ----

