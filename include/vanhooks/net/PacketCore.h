#pragma once

// ===== Consolidated header: PacketCore.h =====
// Merges: ProtocolType, RawPacket, Layer, IPLayer, Packet, PayloadLayer, PacketTrailerLayer, TLVData, PacketUtils
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "Common.h"

// ---- begin ProtocolType.h ----
#include <stdint.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @typedef ProtocolType
	 * Representing all protocols supported by VanHooks
	 */
	typedef uint8_t ProtocolType;

	/**
	 * @typedef ProtocolTypeFamily
	 * Representing a family of protocols
	 */
	typedef uint32_t ProtocolTypeFamily;

	/**
	 * Unknown protocol (or unsupported by VanHooks)
	 */
	const ProtocolType UnknownProtocol = 0;

	/**
	 * Ethernet protocol
	 */
	const ProtocolType Ethernet = 1;

	/**
	 * IPv4 protocol
	 */
	const ProtocolType IPv4 = 2;

	/**
	 * IPv6 protocol
	 */
	const ProtocolType IPv6 = 3;

	/**
	 * IP protocol family (IPv4 and IPv6 protocols)
	 */
	const ProtocolTypeFamily IP = 0x203;

	/**
	 * TCP protocol
	 */
	const ProtocolType TCP = 4;

	/**
	 * UDP protocol
	 */
	const ProtocolType UDP = 5;

	/**
	 * HTTP request protocol
	 */
	const ProtocolType HTTPRequest = 6;

	/**
	 * HTTP response protocol
	 */
	const ProtocolType HTTPResponse = 7;

	/**
	 * HTTP protocol family (HTTP request and HTTP response protocols)
	 */
	const ProtocolTypeFamily HTTP = 0x607;

	/**
	 * ARP protocol
	 */
	const ProtocolType ARP = 8;

	/**
	 * VLAN protocol
	 */
	const ProtocolType VLAN = 9;

	/**
	 * ICMP protocol
	 */
	const ProtocolType ICMP = 10;

	/**
	 * PPPoE session protocol
	 */
	const ProtocolType PPPoESession = 11;

	/**
	 * PPPoE discovery protocol
	 */
	const ProtocolType PPPoEDiscovery = 12;

	/**
	 * PPPoE protocol family (PPPoESession and PPPoEDiscovery protocols)
	 */
	const ProtocolTypeFamily PPPoE = 0xb0c;

	/**
	 * DNS protocol
	 */
	const ProtocolType DNS = 13;

	/**
	 * MPLS protocol
	 */
	const ProtocolType MPLS = 14;

	/**
	 * GRE version 0 protocol
	 */
	const ProtocolType GREv0 = 15;

	/**
	 * GRE version 1 protocol
	 */
	const ProtocolType GREv1 = 16;

	/**
	 * GRE protocol family (GREv0 and GREv1 protocols)
	 */
	const ProtocolTypeFamily GRE = 0xf10;

	/**
	 * PPP for PPTP protocol
	 */
	const ProtocolType PPP_PPTP = 17;

	/**
	 * SSL/TLS protocol
	 */
	const ProtocolType SSL = 18;

	/**
	 * SLL (Linux cooked capture) protocol
	 */
	const ProtocolType SLL = 19;

	/**
	 * DHCP/BOOTP protocol
	 */
	const ProtocolType DHCP = 20;

	/**
	 * Null/Loopback protocol
	 */
	const ProtocolType NULL_LOOPBACK = 21;

	/**
	 * IGMPv1 protocol
	 */
	const ProtocolType IGMPv1 = 22;

	/**
	 * IGMPv2 protocol
	 */
	const ProtocolType IGMPv2 = 23;

	/**
	 * IGMPv3 protocol
	 */
	const ProtocolType IGMPv3 = 24;

	/**
	 * IGMP protocol family (IGMPv1, IGMPv2, IGMPv3)
	 */
	const ProtocolTypeFamily IGMP = 0x161718;

	/**
	 * Generic payload (no specific protocol)
	 */
	const ProtocolType GenericPayload = 25;

	/**
	 * VXLAN protocol
	 */
	const ProtocolType VXLAN = 26;

	/**
	 * SIP request protocol
	 */
	const ProtocolType SIPRequest = 27;

	/**
	 * SIP response protocol
	 */
	const ProtocolType SIPResponse = 28;

	/**
	 * SIP protocol family (SIPRequest and SIPResponse protocols)
	 */
	const ProtocolTypeFamily SIP = 0x1b1c;

	/**
	 * SDP protocol
	 */
	const ProtocolType SDP = 29;

	/**
	 * Packet trailer
	 */
	const ProtocolType PacketTrailer = 30;

	/**
	 * RADIUS protocol
	 */
	const ProtocolType Radius = 31;

	/**
	 * GTPv1 protocol
	 */
	const ProtocolType GTPv1 = 32;

	/**
	 * GTP protocol family (currently only GTPv1)
	 */
	const ProtocolTypeFamily GTP = 0x20;

	/**
	 * IEEE 802.3 Ethernet protocol
	 */
	const ProtocolType EthernetDot3 = 33;

	/**
	 * Border Gateway Protocol (BGP) version 4 protocol
	 */
	const ProtocolType BGP = 34;

	/**
	 * SSH version 2 protocol
	 */
	const ProtocolType SSH = 35;

	/**
	 * IPSec Authentication Header (AH) protocol
	 */
	const ProtocolType AuthenticationHeader = 36;

	/**
	 * IPSec Encapsulating Security Payload (ESP) protocol
	 */
	const ProtocolType ESP = 37;

	/**
	 * IPSec protocol family (AH and ESP protocols)
	 */
	const ProtocolTypeFamily IPSec = 0x2425;

	/**
	 * Dynamic Host Configuration Protocol version 6 (DHCPv6) protocol
	 */
	const ProtocolType DHCPv6 = 38;

	/**
	 * Network Time (NTP) Protocol
	 */
	const ProtocolType NTP = 39;

	/**
	 * Telnet Protocol
	 */
	const ProtocolType Telnet = 40;

	/**
	 * File Transfer (FTP) Protocol
	 */
	const ProtocolType FTP = 41;

	/**
	 * ICMPv6 protocol
	 */
	const ProtocolType ICMPv6 = 42;

	/**
	 * Spanning Tree Protocol
	 */
	const ProtocolType STP = 43;

	/**
	 * Logical Link Control (LLC)
	 */
	const ProtocolType LLC = 44;

	/**
	 * SOME/IP Base protocol
	 */
	const ProtocolType SomeIP = 45;

	/**
	 * Wake On LAN (WOL) Protocol
	 */
	const ProtocolType WakeOnLan = 46;

	/**
	 * NFLOG (Linux Netfilter NFLOG) Protocol
	 */
	const ProtocolType NFLOG = 47;

	/**
	 * TPKT protocol
	 */
	const ProtocolType TPKT = 48;

	/**
	 * VRRP version 2 protocol
	 */
	const ProtocolType VRRPv2 = 49;

	/**
	 * VRRP version 3 protocol
	 */
	const ProtocolType VRRPv3 = 50;

	/**
	 * VRRP protocol family (VRRPv2 and VRRPv3 protocols)
	 */
	const ProtocolTypeFamily VRRP = 0x3132;

	/**
	 * COTP protocol
	 */
	const ProtocolType COTP = 51;

	/**
	 * SLL2 protocol
	 */
	const ProtocolType SLL2 = 52;

	/**
	 * S7COMM protocol
	 */
	const ProtocolType S7COMM = 53;

	/*
	 * SMTP protocol
	 */
	const ProtocolType SMTP = 54;

	/*
	 * LDAP protocol
	 */
	const ProtocolType LDAP = 55;

	/**
	 * An enum representing OSI model layers
	 */
	enum OsiModelLayer
	{
		/** Physical layer (layer 1) */
		OsiModelPhysicalLayer = 1,
		/** Data link layer (layer 2) */
		OsiModelDataLinkLayer = 2,
		/** Network layer (layer 3) */
		OsiModelNetworkLayer = 3,
		/** Transport layer (layer 4) */
		OsiModelTransportLayer = 4,
		/** Session layer (layer 5) */
		OsiModelSesionLayer = 5,
		/** Presentation layer (layer 6) */
		OsiModelPresentationLayer = 6,
		/** Application layer (layer 7) */
		OsiModelApplicationLayer = 7,
		/** Unknown / null layer */
		OsiModelLayerUnknown = 8
	};

}  // namespace vanhooks::net
// ---- end ProtocolType.h ----

// ---- begin RawPacket.h ----
#include <stdint.h>
#ifdef _MSC_VER
#	include <WinSock2.h>
#	include <time.h>
#else
#	include <sys/time.h>
#endif
#include <stddef.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * An enum describing all known link layer type. Taken from: http://www.tcpdump.org/linktypes.html .
	 */
	enum LinkLayerType
	{
		/** BSD loopback encapsulation */
		LINKTYPE_NULL = 0,
		/** IEEE 802.3 Ethernet */
		LINKTYPE_ETHERNET = 1,
		/** AX.25 packet */
		LINKTYPE_AX25 = 3,
		/** IEEE 802.5 Token Ring */
		LINKTYPE_IEEE802_5 = 6,
		/** ARCNET Data Packets */
		LINKTYPE_ARCNET_BSD = 7,
		/** SLIP, encapsulated with a LINKTYPE_SLIP header */
		LINKTYPE_SLIP = 8,
		/** PPP, as per RFC 1661 and RFC 1662 */
		LINKTYPE_PPP = 9,
		/** FDDI, as specified by ANSI INCITS 239-1994 */
		LINKTYPE_FDDI = 10,
		/** Raw IP */
		LINKTYPE_DLT_RAW1 = 12,
		/** Raw IP (OpenBSD) */
		LINKTYPE_DLT_RAW2 = 14,
		/** PPP in HDLC-like framing, as per RFC 1662, or Cisco PPP with HDLC framing, as per section 4.3.1 of RFC 1547
		 */
		LINKTYPE_PPP_HDLC = 50,
		/** PPPoE */
		LINKTYPE_PPP_ETHER = 51,
		/** RFC 1483 LLC/SNAP-encapsulated ATM */
		LINKTYPE_ATM_RFC1483 = 100,
		/** Raw IP */
		LINKTYPE_RAW = 101,
		/** Cisco PPP with HDLC framing */
		LINKTYPE_C_HDLC = 104,
		/** IEEE 802.11 wireless LAN */
		LINKTYPE_IEEE802_11 = 105,
		/** Frame Relay */
		LINKTYPE_FRELAY = 107,
		/** OpenBSD loopback encapsulation */
		LINKTYPE_LOOP = 108,
		/** Linux "cooked" capture encapsulation */
		LINKTYPE_LINUX_SLL = 113,
		/** Apple LocalTalk */
		LINKTYPE_LTALK = 114,
		/** OpenBSD pflog */
		LINKTYPE_PFLOG = 117,
		/** Prism monitor mode information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_PRISM = 119,
		/** RFC 2625 IP-over-Fibre Channel */
		LINKTYPE_IP_OVER_FC = 122,
		/** ATM traffic, encapsulated as per the scheme used by SunATM devices */
		LINKTYPE_SUNATM = 123,
		/** Radiotap link-layer information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_RADIOTAP = 127,
		/** ARCNET Data Packets, as described by the ARCNET Trade Association standard ATA 878.1-1999 */
		LINKTYPE_ARCNET_LINUX = 129,
		/** Apple IP-over-IEEE 1394 cooked header */
		LINKTYPE_APPLE_IP_OVER_IEEE1394 = 138,
		/** Signaling System 7 Message Transfer Part Level 2 */
		LINKTYPE_MTP2_WITH_PHDR = 139,
		/** Signaling System 7 Message Transfer Part Level 2 */
		LINKTYPE_MTP2 = 140,
		/** Signaling System 7 Message Transfer Part Level 3 */
		LINKTYPE_MTP3 = 141,
		/** Signaling System 7 Signalling Connection Control Part */
		LINKTYPE_SCCP = 142,
		/** Signaling System 7 Signalling Connection Control Part */
		LINKTYPE_DOCSIS = 143,
		/** Linux-IrDA packets */
		LINKTYPE_LINUX_IRDA = 144,
		/** Reserved for private use */
		LINKTYPE_USER0 = 147,
		/** Reserved for private use */
		LINKTYPE_USER1 = 148,
		/** Reserved for private use */
		LINKTYPE_USER2 = 149,
		/** Reserved for private use */
		LINKTYPE_USER3 = 150,
		/** Reserved for private use */
		LINKTYPE_USER4 = 151,
		/** Reserved for private use */
		LINKTYPE_USER5 = 152,
		/** Reserved for private use */
		LINKTYPE_USER6 = 153,
		/** Reserved for private use */
		LINKTYPE_USER7 = 154,
		/** Reserved for private use */
		LINKTYPE_USER8 = 155,
		/** Reserved for private use */
		LINKTYPE_USER9 = 156,
		/** Reserved for private use */
		LINKTYPE_USER10 = 157,
		/** Reserved for private use */
		LINKTYPE_USER11 = 158,
		/** Reserved for private use */
		LINKTYPE_USER12 = 159,
		/** Reserved for private use */
		LINKTYPE_USER13 = 160,
		/** Reserved for private use */
		LINKTYPE_USER14 = 161,
		/** Reserved for private use */
		LINKTYPE_USER15 = 162,
		/** AVS monitor mode information followed by an 802.11 header */
		LINKTYPE_IEEE802_11_AVS = 163,
		/** BACnet MS/TP frames */
		LINKTYPE_BACNET_MS_TP = 165,
		/** PPP in HDLC-like encapsulation, like LINKTYPE_PPP_HDLC, but with the 0xff address byte replaced by a
		 * direction indication - 0x00 for incoming and 0x01 for outgoing */
		LINKTYPE_PPP_PPPD = 166,
		/** General Packet Radio Service Logical Link Control */
		LINKTYPE_GPRS_LLC = 169,
		/** Transparent-mapped generic framing procedure */
		LINKTYPE_GPF_T = 170,
		/** Frame-mapped generic framing procedure */
		LINKTYPE_GPF_F = 171,
		/** Link Access Procedures on the D Channel (LAPD) frames */
		LINKTYPE_LINUX_LAPD = 177,
		/** Bluetooth HCI UART transport layer */
		LINKTYPE_BLUETOOTH_HCI_H4 = 187,
		/** USB packets, beginning with a Linux USB header */
		LINKTYPE_USB_LINUX = 189,
		/** Per-Packet Information information */
		LINKTYPE_PPI = 192,
		/** IEEE 802.15.4 wireless Personal Area Network */
		LINKTYPE_IEEE802_15_4 = 195,
		/** Various link-layer types, with a pseudo-header, for SITA */
		LINKTYPE_SITA = 196,
		/** Various link-layer types, with a pseudo-header, for Endace DAG cards; encapsulates Endace ERF record */
		LINKTYPE_ERF = 197,
		/** Bluetooth HCI UART transport layer */
		LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201,
		/** AX.25 packet, with a 1-byte KISS header containing a type indicator */
		LINKTYPE_AX25_KISS = 202,
		/** Link Access Procedures on the D Channel (LAPD) frames */
		LINKTYPE_LAPD = 203,
		/** PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header with a zero value meaning
		 * "received by this host" and a non-zero value meaning  "sent by this host" */
		LINKTYPE_PPP_WITH_DIR = 204,
		/** Cisco PPP with HDLC framing */
		LINKTYPE_C_HDLC_WITH_DIR = 205,
		/** Frame Relay */
		LINKTYPE_FRELAY_WITH_DIR = 206,
		/** IPMB over an I2C circuit */
		LINKTYPE_IPMB_LINUX = 209,
		/** IEEE 802.15.4 wireless Personal Area Network */
		LINKTYPE_IEEE802_15_4_NONASK_PHY = 215,
		/** USB packets, beginning with a Linux USB header */
		LINKTYPE_USB_LINUX_MMAPPED = 220,
		/** Fibre Channel FC-2 frames, beginning with a Frame_Header */
		LINKTYPE_FC_2 = 224,
		/** Fibre Channel FC-2 frames */
		LINKTYPE_FC_2_WITH_FRAME_DELIMS = 225,
		/** Solaris ipnet pseudo-header */
		LINKTYPE_IPNET = 226,
		/** CAN (Controller Area Network) frames, with a pseudo-header as supplied by Linux SocketCAN */
		LINKTYPE_CAN_SOCKETCAN = 227,
		/** Raw IPv4; the packet begins with an IPv4 header */
		LINKTYPE_IPV4 = 228,
		/** Raw IPv6; the packet begins with an IPv6 header */
		LINKTYPE_IPV6 = 229,
		/** IEEE 802.15.4 wireless Personal Area Network, without the FCS at the end of the frame */
		LINKTYPE_IEEE802_15_4_NOFCS = 230,
		/** Raw D-Bus messages, starting with the endianness flag, followed by the message type, etc., but without the
		 * authentication handshake before the message sequence */
		LINKTYPE_DBUS = 231,
		/** DVB-CI (DVB Common Interface for communication between a PC Card module and a DVB receiver), with the
		 * message format specified by the PCAP format for DVB-CI specification */
		LINKTYPE_DVB_CI = 235,
		/** Variant of 3GPP TS 27.010 multiplexing protocol (similar to, but not the same as, 27.010) */
		LINKTYPE_MUX27010 = 236,
		/** D_PDUs as described by NATO standard STANAG 5066, starting with the synchronization sequence, and including
		 * both header and data CRCs */
		LINKTYPE_STANAG_5066_D_PDU = 237,
		/** Linux netlink NETLINK NFLOG socket log messages */
		LINKTYPE_NFLOG = 239,
		/** Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an
		 * Ethernet frame, beginning with the MAC header and ending with the FCS */
		LINKTYPE_NETANALYZER = 240,
		/** Pseudo-header for Hilscher Gesellschaft für Systemautomation mbH netANALYZER devices, followed by an
		 * Ethernet frame, beginning with the preamble, SFD, and MAC header, and ending with the FCS */
		LINKTYPE_NETANALYZER_TRANSPARENT = 241,
		/** IP-over-InfiniBand, as specified by RFC 4391 section 6 */
		LINKTYPE_IPOIB = 242,
		/** MPEG-2 Transport Stream transport packets, as specified by ISO 13818-1/ITU-T Recommendation H.222.0 */
		LINKTYPE_MPEG_2_TS = 243,
		/** Pseudo-header for ng4T GmbH's UMTS Iub/Iur-over-ATM and Iub/Iur-over-IP format as used by their ng40
		 * protocol tester */
		LINKTYPE_NG40 = 244,
		/** Pseudo-header for NFC LLCP packet captures, followed by frame data for the LLCP Protocol as specified by
		 * NFCForum-TS-LLCP_1.1 */
		LINKTYPE_NFC_LLCP = 245,
		/** Raw InfiniBand frames, starting with the Local Routing Header */
		LINKTYPE_INFINIBAND = 247,
		/** SCTP packets, as defined by RFC 4960, with no lower-level protocols such as IPv4 or IPv6 */
		LINKTYPE_SCTP = 248,
		/** USB packets, beginning with a USBPcap header */
		LINKTYPE_USBPCAP = 249,
		/** Serial-line packet header for the Schweitzer Engineering Laboratories "RTAC" product */
		LINKTYPE_RTAC_SERIAL = 250,
		/** Bluetooth Low Energy air interface Link Layer packets */
		LINKTYPE_BLUETOOTH_LE_LL = 251,
		/** Linux Netlink capture encapsulation */
		LINKTYPE_NETLINK = 253,
		/** Bluetooth Linux Monitor encapsulation of traffic for the BlueZ stack */
		LINKTYPE_BLUETOOTH_LINUX_MONITOR = 254,
		/** Bluetooth Basic Rate and Enhanced Data Rate baseband packets */
		LINKTYPE_BLUETOOTH_BREDR_BB = 255,
		/** Bluetooth Low Energy link-layer packets */
		LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR = 256,
		/** PROFIBUS data link layer packets, as specified by IEC standard 61158-6-3 */
		LINKTYPE_PROFIBUS_DL = 257,
		/** Apple PKTAP capture encapsulation */
		LINKTYPE_PKTAP = 258,
		/** Ethernet-over-passive-optical-network packets */
		LINKTYPE_EPON = 259,
		/** IPMI trace packets, as specified by Table 3-20 "Trace Data Block Format" in the PICMG HPM.2 specification */
		LINKTYPE_IPMI_HPM_2 = 260,
		/** Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profiles R1 and R2 captures */
		LINKTYPE_ZWAVE_R1_R2 = 261,
		/** Per Joshua Wright <jwright@hasborg.com>, formats for Z-Wave RF profile R3 captures */
		LINKTYPE_ZWAVE_R3 = 262,
		/** Formats for WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol common packet
		 * structure captures */
		LINKTYPE_WATTSTOPPER_DLM = 263,
		/** Messages between ISO 14443 contactless smartcards (Proximity Integrated Circuit Card, PICC) and card readers
		 * (Proximity Coupling Device, PCD), with the message format specified by the PCAP format for ISO14443
		 * specification */
		LINKTYPE_ISO_14443 = 264,
		/** Linux "cooked" capture encapsulation v2 */
		LINKTYPE_LINUX_SLL2 = 276,
		/** Set if interface ID for a packet of a pcapng file is too high */
		LINKTYPE_INVALID = 0xFFFF
	};

	/**
	 * Max packet size supported
	 */
#define VH_MAX_PACKET_SIZE 65536

	/**
	 * @class RawPacket
	 * This class holds the packet as raw (not parsed) data. The data is held as byte array. In addition to the data
	 * itself every instance also holds a timestamp representing the time the packet was received by the NIC. RawPacket
	 * instance isn't read only. The user can change the packet data, add or remove data, etc.
	 */
	class RawPacket
	{
	protected:
		uint8_t* m_RawData;
		int m_RawDataLen;
		int m_FrameLength;
		timespec m_TimeStamp;
		bool m_DeleteRawDataAtDestructor;
		bool m_RawPacketSet;
		LinkLayerType m_LinkLayerType;
		void init(bool deleteRawDataAtDestructor = true);
		void copyDataFrom(const RawPacket& other, bool allocateData = true);

	public:
		/**
		 * A constructor that receives a pointer to the raw data (allocated elsewhere). This constructor is usually used
		 * when packet is captured using a packet capturing engine (like libPcap. WinPcap, Npcap, PF_RING, etc.). The
		 * capturing engine allocates the raw data memory and give the user a pointer to it + a timestamp it has arrived
		 * to the device
		 * @param[in] pRawData A pointer to the raw data
		 * @param[in] rawDataLen The raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC (in usec precision)
		 * @param[in] deleteRawDataAtDestructor An indicator whether raw data pointer should be freed when the instance
		 * is freed or not. If set to 'true' than pRawData will be freed when instanced is being freed
		 * @param[in] layerType The link layer type of this raw packet. The default is Ethernet
		 */
		RawPacket(const uint8_t* pRawData, int rawDataLen, timeval timestamp, bool deleteRawDataAtDestructor,
		          LinkLayerType layerType = LINKTYPE_ETHERNET);

		/**
		 * A constructor that receives a pointer to the raw data (allocated elsewhere). This constructor is usually used
		 * when packet is captured using a packet capturing engine (like libPcap. WinPcap, Npcap, PF_RING, etc.). The
		 * capturing engine allocates the raw data memory and give the user a pointer to it + a timestamp it has arrived
		 * to the device
		 * @param[in] pRawData A pointer to the raw data
		 * @param[in] rawDataLen The raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC (in nsec precision)
		 * @param[in] deleteRawDataAtDestructor An indicator whether raw data pointer should be freed when the instance
		 * is freed or not. If set to 'true' than pRawData will be freed when instanced is being freed
		 * @param[in] layerType The link layer type of this raw packet. The default is Ethernet
		 */
		RawPacket(const uint8_t* pRawData, int rawDataLen, timespec timestamp, bool deleteRawDataAtDestructor,
		          LinkLayerType layerType = LINKTYPE_ETHERNET);

		/**
		 * A default constructor that initializes class'es attributes to default value:
		 * - data pointer is set to nullptr
		 * - data length is set to 0
		 * - deleteRawDataAtDestructor is set to 'true'
		 * @todo timestamp isn't set here to a default value
		 */
		RawPacket();

		/**
		 * A destructor for this class. Frees the raw data if deleteRawDataAtDestructor was set to 'true'
		 */
		virtual ~RawPacket();

		/**
		 * A copy constructor that copies all data from another instance. Notice all raw data is copied (using memcpy),
		 * so when the original or the other instance are freed, the other won't be affected
		 * @param[in] other The instance to copy from
		 */
		RawPacket(const RawPacket& other);

		/**
		 * Assignment operator overload for this class. When using this operator on an already initialized RawPacket
		 * instance, the original raw data is freed first. Then the other instance is copied to this instance, the same
		 * way the copy constructor works
		 * @todo free raw data only if deleteRawDataAtDestructor was set to 'true'
		 * @param[in] other The instance to copy from
		 */
		RawPacket& operator=(const RawPacket& other);

		/**
		 * @return RawPacket object type. Each derived class should return a different value
		 */
		virtual uint8_t getObjectType() const
		{
			return 0;
		}

		/**
		 * Set a raw data. If data was already set and deleteRawDataAtDestructor was set to 'true' the old data will be
		 * freed first
		 * @param[in] pRawData A pointer to the new raw data
		 * @param[in] rawDataLen The new raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC (in usec precision)
		 * @param[in] layerType The link layer type for this raw data
		 * @param[in] frameLength When reading from pcap files, sometimes the captured length is different from the
		 * actual packet length. This parameter represents the packet length. This parameter is optional, if not set or
		 * set to -1 it is assumed both lengths are equal
		 * @return True if raw data was set successfully, false otherwise
		 */
		virtual bool setRawData(const uint8_t* pRawData, int rawDataLen, timeval timestamp,
		                        LinkLayerType layerType = LINKTYPE_ETHERNET, int frameLength = -1);

		/**
		 * Set a raw data. If data was already set and deleteRawDataAtDestructor was set to 'true' the old data will be
		 * freed first
		 * @param[in] pRawData A pointer to the new raw data
		 * @param[in] rawDataLen The new raw data length in bytes
		 * @param[in] timestamp The timestamp packet was received by the NIC (in nsec precision)
		 * @param[in] layerType The link layer type for this raw data
		 * @param[in] frameLength When reading from pcap files, sometimes the captured length is different from the
		 * actual packet length. This parameter represents the packet length. This parameter is optional, if not set or
		 * set to -1 it is assumed both lengths are equal
		 * @return True if raw data was set successfully, false otherwise
		 */
		virtual bool setRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp,
		                        LinkLayerType layerType = LINKTYPE_ETHERNET, int frameLength = -1);

		/**
		 * Initialize a raw packet with data. The main difference between this method and setRawData() is that
		 * setRawData() is meant for replacing the data in an existing raw packet, whereas this method is meant to be
		 * used right after constructing a raw packet using the default c'tor, before setting any data
		 * @param pRawData A pointer to the new raw data
		 * @param rawDataLen The new raw data length in bytes
		 * @param timestamp The timestamp packet was received by the NIC (in nsec precision)
		 * @param layerType The link layer type for this raw data
		 * @return True if raw data was set successfully, false otherwise
		 */
		bool initWithRawData(const uint8_t* pRawData, int rawDataLen, timespec timestamp,
		                     LinkLayerType layerType = LINKTYPE_ETHERNET);

		/**
		 * Get raw data pointer
		 * @return A read-only pointer to the raw data
		 */
		const uint8_t* getRawData() const
		{
			return m_RawData;
		}

		/**
		 * Get the link layer type
		 * @return the type of the link layer
		 */
		LinkLayerType getLinkLayerType() const
		{
			return m_LinkLayerType;
		}

		/**
		 * This static method validates whether a link type integer value is valid
		 * @param[in] linkTypeValue Link type integer value
		 * @return True if the link type value is valid and can be casted into LinkLayerType enum, false otherwise
		 */
		static bool isLinkTypeValid(int linkTypeValue);

		/**
		 * Get raw data length in bytes
		 * @return Raw data length in bytes
		 */
		int getRawDataLen() const
		{
			return m_RawDataLen;
		}

		/**
		 * Get frame length in bytes
		 * @return frame length in bytes
		 */
		int getFrameLength() const
		{
			return m_FrameLength;
		}
		/**
		 * Get raw data timestamp
		 * @return Raw data timestamp
		 */
		timespec getPacketTimeStamp() const
		{
			return m_TimeStamp;
		}

		/**
		 * Set raw packet timestamp with usec precision
		 * @param[in] timestamp The timestamp to set (with usec precision)
		 * @return True if timestamp was set successfully, false otherwise
		 */
		virtual bool setPacketTimeStamp(timeval timestamp);

		/**
		 * Set raw packet timestamp with nsec precision
		 * @param[in] timestamp The timestamp to set (with nsec precision)
		 * @return True if timestamp was set successfully, false otherwise
		 */
		virtual bool setPacketTimeStamp(timespec timestamp);

		/**
		 * Get an indication whether raw data was already set for this instance.
		 * @return True if raw data was set for this instance. Raw data can be set using the non-default constructor,
		 * using setRawData(), using the copy constructor or using the assignment operator. Returns false otherwise, for
		 * example: if the instance was created using the default constructor or clear() was called
		 */
		bool isPacketSet() const
		{
			return m_RawPacketSet;
		}

		/**
		 * Clears all members of this instance, meaning setting raw data to nullptr, raw data length to 0, etc.
		 * Currently raw data is always freed, even if deleteRawDataAtDestructor was set to 'false'
		 * @todo deleteRawDataAtDestructor was set to 'true', don't free the raw data
		 * @todo set timestamp to a default value as well
		 */
		virtual void clear();

		/**
		 * Append data to the end of current data. This method works without allocating more memory, it just uses
		 * memcpy() to copy dataToAppend at the end of the current data. This means that the method assumes this memory
		 * was already allocated by the user. If it isn't the case then this method will cause memory corruption
		 * @param[in] dataToAppend A pointer to the data to append to current raw data
		 * @param[in] dataToAppendLen Length in bytes of dataToAppend
		 */
		virtual void appendData(const uint8_t* dataToAppend, size_t dataToAppendLen);

		/**
		 * Insert new data at some index of the current data and shift the remaining old data to the end. This method
		 * works without allocating more memory, it just copies dataToAppend at the relevant index and shifts the
		 * remaining data to the end. This means that the method assumes this memory was already allocated by the user.
		 * If it isn't the case then this method will cause memory corruption
		 * @param[in] atIndex The index to insert the new data to
		 * @param[in] dataToInsert A pointer to the new data to insert
		 * @param[in] dataToInsertLen Length in bytes of dataToInsert
		 */
		virtual void insertData(int atIndex, const uint8_t* dataToInsert, size_t dataToInsertLen);

		/**
		 * Remove certain number of bytes from current raw data buffer. All data after the removed bytes will be shifted
		 * back
		 * @param[in] atIndex The index to start removing bytes from
		 * @param[in] numOfBytesToRemove Number of bytes to remove
		 * @return True if all bytes were removed successfully, or false if atIndex+numOfBytesToRemove is out-of-bounds
		 * of the raw data buffer
		 */
		virtual bool removeData(int atIndex, size_t numOfBytesToRemove);

		/**
		 * Re-allocate raw packet buffer meaning add size to it without losing the current packet data. This method
		 * allocates the required buffer size as instructed by the use and then copies the raw data from the current
		 * allocated buffer to the new one. This method can become useful if the user wants to insert or append data to
		 * the raw data, and the previous allocated buffer is too small, so the user wants to allocate a larger buffer
		 * and get RawPacket instance to point to it
		 * @param[in] newBufferLength The new buffer length as required by the user. The method is responsible to
		 * allocate the memory
		 * @return True if data was reallocated successfully, false otherwise
		 */
		virtual bool reallocateData(size_t newBufferLength);
	};

}  // namespace vanhooks::net
// ---- end RawPacket.h ----

// ---- begin Layer.h ----
#include <stdint.h>
#include <stdio.h>
#include <string>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class IDataContainer
	 * An interface (virtual abstract class) that indicates an object that holds a pointer to a buffer data. The Layer
	 * class is an example of such object, hence it inherits this interface
	 */
	class IDataContainer
	{
	public:
		/**
		 * Get a pointer to the data
		 * @param[in] offset Get a pointer in a certain offset. Default is 0 - get a pointer to start of data
		 * @return A pointer to the data
		 */
		virtual uint8_t* getDataPtr(size_t offset = 0) const = 0;

		virtual ~IDataContainer()
		{}
	};

	class Packet;

	/**
	 * @class Layer
	 * Layer is the base class for all protocol layers. Each protocol supported in VanHooks has a class that
	 * inherits Layer.
	 * The protocol layer class expose all properties and methods relevant for viewing and editing protocol fields.
	 * For example: a pointer to a structured header (e.g tcphdr, iphdr, etc.), protocol header size, payload size,
	 * compute fields that can be automatically computed, print protocol data to string, etc.
	 * Each protocol instance is obviously part of a protocol stack (which construct a packet). This protocol stack is
	 * represented in VanHooks in a linked list, and each layer is an element in this list. That's why each layer
	 * has properties to the next and previous layer in the protocol stack. The Layer class, as a base class, is
	 * abstract and the user can't create an instance of it (it has a private constructor). Each layer holds a pointer
	 * to the relevant place in the packet. The layer sees all the data from this pointer forward until the end of the
	 * packet. Here is an example packet showing this concept:
	 *
	 * @verbatim
	 * ====================================================
	 * |Eth       |IPv4       |TCP       |Packet          |
	 * |Header    |Header     |Header    |Payload         |
	 * ====================================================
	 *
	 * |--------------------------------------------------|
	 * EthLayer data
	 *            |---------------------------------------|
	 *            IPv4Layer data
	 *                        |---------------------------|
	 *                        TcpLayer data
	 *                                   |----------------|
	 *                                   PayloadLayer data
	 * @endverbatim
	 *
	 */
	class Layer : public IDataContainer
	{
		friend class Packet;

	public:
		/**
		 * A destructor for this class. Frees the data if it was allocated by the layer constructor (see
		 * isAllocatedToPacket() for more info)
		 */
		virtual ~Layer();

		/**
		 * @return A pointer to the next layer in the protocol stack or nullptr if the layer is the last one
		 */
		Layer* getNextLayer() const
		{
			return m_NextLayer;
		}

		/**
		 * @return A pointer to the previous layer in the protocol stack or nullptr if the layer is the first one
		 */
		Layer* getPrevLayer() const
		{
			return m_PrevLayer;
		}

		/**
		 * @return The protocol enum
		 */
		ProtocolType getProtocol() const
		{
			return m_Protocol;
		}

		/**
		 * Check if the layer's protocol matches a protocol family
		 * @param protocolTypeFamily The protocol family to check
		 * @return True if the layer's protocol matches the protocol family, false otherwise
		 */
		bool isMemberOfProtocolFamily(ProtocolTypeFamily protocolTypeFamily) const;

		/**
		 * @return A pointer to the layer raw data. In most cases it'll be a pointer to the first byte of the header
		 */
		uint8_t* getData() const
		{
			return m_Data;
		}

		/**
		 * @return The length in bytes of the data from the first byte of the header until the end of the packet
		 */
		size_t getDataLen() const
		{
			return m_DataLen;
		}

		/**
		 * @return A pointer for the layer payload, meaning the first byte after the header
		 */
		uint8_t* getLayerPayload() const
		{
			return m_Data + getHeaderLen();
		}

		/**
		 * @return The size in bytes of the payload
		 */
		size_t getLayerPayloadSize() const
		{
			return m_DataLen - getHeaderLen();
		}

		/**
		 * Raw data in layers can come from one of sources:
		 * 1. from an existing packet - this is the case when parsing packets received from files or the network. In
		 * this case the data was already allocated by someone else, and layer only holds the pointer to the relevant
		 * place inside this data
		 * 2. when creating packets, data is allocated when layer is created. In this case the layer is responsible for
		 * freeing it as well
		 *
		 * @return Returns true if the data was allocated by an external source (a packet) or false if it was allocated
		 * by the layer itself
		 */
		bool isAllocatedToPacket() const
		{
			return m_Packet != nullptr;
		}

		/**
		 * Copy the raw data of this layer to another array
		 * @param[out] toArr The destination byte array
		 */
		void copyData(uint8_t* toArr) const;

		// implement abstract methods

		uint8_t* getDataPtr(size_t offset = 0) const
		{
			return (uint8_t*)(m_Data + offset);
		}

		// abstract methods

		/**
		 * Each layer is responsible for parsing the next layer
		 */
		virtual void parseNextLayer() = 0;

		/**
		 * @return The header length in bytes
		 */
		virtual size_t getHeaderLen() const = 0;

		/**
		 * Each layer can compute field values automatically using this method. This is an abstract method
		 */
		virtual void computeCalculateFields() = 0;

		/**
		 * @return A string representation of the layer most important data (should look like the layer description in
		 * Wireshark)
		 */
		virtual std::string toString() const = 0;

		/**
		 * @return The OSI Model layer this protocol belongs to
		 */
		virtual OsiModelLayer getOsiModelLayer() const = 0;

	protected:
		uint8_t* m_Data;
		size_t m_DataLen;
		Packet* m_Packet;
		ProtocolType m_Protocol;
		Layer* m_NextLayer;
		Layer* m_PrevLayer;
		bool m_IsAllocatedInPacket;

		Layer()
		    : m_Data(nullptr), m_DataLen(0), m_Packet(nullptr), m_Protocol(UnknownProtocol), m_NextLayer(nullptr),
		      m_PrevLayer(nullptr), m_IsAllocatedInPacket(false)
		{}

		Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol = UnknownProtocol)
		    : m_Data(data), m_DataLen(dataLen), m_Packet(packet), m_Protocol(protocol), m_NextLayer(nullptr),
		      m_PrevLayer(prevLayer), m_IsAllocatedInPacket(false)
		{}

		// Copy c'tor
		Layer(const Layer& other);
		Layer& operator=(const Layer& other);

		void setNextLayer(Layer* nextLayer)
		{
			m_NextLayer = nextLayer;
		}
		void setPrevLayer(Layer* prevLayer)
		{
			m_PrevLayer = prevLayer;
		}

		virtual bool extendLayer(int offsetInLayer, size_t numOfBytesToExtend);
		virtual bool shortenLayer(int offsetInLayer, size_t numOfBytesToShorten);
	};

}  // namespace vanhooks::net

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::Layer& layer)
{
	os << layer.toString();
	return os;
}
// ---- end Layer.h ----

// ---- begin IPLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @class IPLayer
	 * This is an interface (abstract class) implemented in the IP layers (IPv4Layer and IPv6Layer).
	 * It provides methods to fetch the source and destination IP addresses in an abdtract way
	 * that hides the IP type (IPv4 or IPv6). This is useful for use-cases in which the IP type doesn't matter.
	 * For example: if you're only interested in printing the IP address the IP type shouldn't matter.
	 */
	class IPLayer
	{
	protected:
		IPLayer()
		{}

	public:
		/**
		 * An abstract method to get the source IP address
		 * @return An IPAddress object containing the source address
		 */
		virtual IPAddress getSrcIPAddress() const = 0;

		/**
		 * An abstract method to get the destination IP address
		 * @return An IPAddress object containing the destination address
		 */
		virtual IPAddress getDstIPAddress() const = 0;

		/**
		 * An empty destructor
		 */
		virtual ~IPLayer()
		{}
	};
}  // namespace vanhooks::net
// ---- end IPLayer.h ----

// ---- begin Packet.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class Packet
	 * This class represents a parsed packet. It contains the raw data (RawPacket instance), and a linked list of
	 * layers, each layer is a parsed protocol that this packet contains. The layers linked list is ordered where the
	 * first layer is the lowest in the packet (currently it's always Ethernet protocol as VanHooks supports only
	 * Ethernet packets), the next layer will be L2.5 or L3 (e.g VLAN, IPv4, IPv6, etc.), and so on. etc.), etc. The
	 * last layer in the linked list will be the highest in the packet. For example: for a standard HTTP request packet
	 * the layer will look like this: EthLayer -> IPv4Layer -> TcpLayer -> HttpRequestLayer <BR> Packet instance isn't
	 * read only. The user can add or remove layers, update current layer, etc.
	 */
	class Packet
	{
		friend class Layer;

	private:
		RawPacket* m_RawPacket;
		Layer* m_FirstLayer;
		Layer* m_LastLayer;
		size_t m_MaxPacketLen;
		bool m_FreeRawPacket;
		bool m_CanReallocateData;

	public:
		/**
		 * A constructor for creating a new packet (with no layers).
		 * When using this constructor an empty raw buffer is allocated (with the size of maxPacketLen) and a new
		 * RawPacket is created
		 * @param[in] maxPacketLen The expected packet length in bytes
		 */
		explicit Packet(size_t maxPacketLen = 1);

		/**
		 * A constructor for creating a new packet with a buffer that is pre-allocated by the user.
		 * The packet is created empty (with no layers), which means the constructor doesn't parse the data in the
		 * buffer. Instead, all of the raw data of this packet it written to this buffer: whenever a layer is added,
		 * it's data is written to this buffer. The buffer isn't freed and it's content isn't erased when the packet
		 * object is deleted. This constructor is useful when you already have a memory buffer and you want to create
		 * packet data in it.
		 * @param[in] buffer A pointer to a pre-allocated memory buffer
		 * @param[in] bufferSize The size of the buffer
		 */
		Packet(uint8_t* buffer, size_t bufferSize);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that
		 * came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't copied)
		 * and the RawPacket is parsed, meaning all layers are created and linked to each other in the right order. In
		 * this overload of the constructor the user can specify whether to free the instance of raw packet when the
		 * Packet is free or not
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] freeRawPacket Optional parameter. A flag indicating if the destructor should also call the raw
		 * packet destructor or not. Default value is false
		 * @param[in] parseUntil Optional parameter. Parse the packet until you reach a certain protocol (inclusive).
		 * Can be useful for cases when you need to parse only up to a certain layer and want to avoid the performance
		 * impact and memory consumption of parsing the whole packet. Default value is ::UnknownProtocol which means
		 * don't take this parameter into account
		 * @param[in] parseUntilLayer Optional parameter. Parse the packet until you reach a certain layer in the OSI
		 * model (inclusive). Can be useful for cases when you need to parse only up to a certain OSI layer (for example
		 * transport layer) and want to avoid the performance impact and memory consumption of parsing the whole packet.
		 * Default value is ::OsiModelLayerUnknown which means don't take this parameter into account
		 */
		explicit Packet(RawPacket* rawPacket, bool freeRawPacket = false, ProtocolType parseUntil = UnknownProtocol,
		                OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that
		 * came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't copied)
		 * and the RawPacket is parsed, meaning all layers are created and linked to each other in the right order. In
		 * this overload of the constructor the user can specify whether to free the instance of raw packet when the
		 * Packet is free or not. This constructor should be used to parse the packet up to a certain layer
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] parseUntil Parse the packet until you reach a certain protocol (inclusive). Can be useful for
		 * cases when you need to parse only up to a certain layer and want to avoid the performance impact and memory
		 * consumption of parsing the whole packet
		 */
		explicit Packet(RawPacket* rawPacket, ProtocolType parseUntil);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that
		 * came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't copied)
		 * and the RawPacket is parsed, meaning all layers are created and linked to each other in the right order. In
		 * this overload of the constructor the user can specify whether to free the instance of raw packet when the
		 * Packet is free or not. This constructor should be used to parse the packet up to a certain layer
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] parseUntilFamily Parse the packet until you reach a certain protocol family (inclusive). Can be
		 * useful for cases when you need to parse only up to a certain layer and want to avoid the performance impact
		 * and memory consumption of parsing the whole packet
		 */
		explicit Packet(RawPacket* rawPacket, ProtocolTypeFamily parseUntilFamily);

		/**
		 * A constructor for creating a packet out of already allocated RawPacket. Very useful when parsing packets that
		 * came from the network. When using this constructor a pointer to the RawPacket is saved (data isn't copied)
		 * and the RawPacket is parsed, meaning all layers are created and linked to each other in the right order. In
		 * this overload of the constructor the user can specify whether to free the instance of raw packet when the
		 * Packet is free or not. This constructor should be used to parse the packet up to a certain layer in the OSI
		 * model
		 * @param[in] rawPacket A pointer to the raw packet
		 * @param[in] parseUntilLayer Optional parameter. Parse the packet until you reach a certain layer in the OSI
		 * model (inclusive). Can be useful for cases when you need to parse only up to a certain OSI layer (for example
		 * transport layer) and want to avoid the performance impact and memory consumption of parsing the whole packet
		 */
		explicit Packet(RawPacket* rawPacket, OsiModelLayer parseUntilLayer);

		/**
		 * A destructor for this class. Frees all layers allocated by this instance (Notice: it doesn't free layers that
		 * weren't allocated by this class, for example layers that were added by addLayer() or insertLayer() ). In
		 * addition it frees the raw packet if it was allocated by this instance (meaning if it was allocated by this
		 * instance constructor)
		 */
		virtual ~Packet()
		{
			destructPacketData();
		}

		/**
		 * A copy constructor for this class. This copy constructor copies all the raw data and re-create all layers. So
		 * when the original Packet is being freed, no data will be lost in the copied instance
		 * @param[in] other The instance to copy from
		 */
		Packet(const Packet& other)
		{
			copyDataFrom(other);
		}

		/**
		 * Assignment operator overloading. It first frees all layers allocated by this instance (Notice: it doesn't
		 * free layers that weren't allocated by this class, for example layers that were added by addLayer() or
		 * insertLayer() ). In addition it frees the raw packet if it was allocated by this instance (meaning if it was
		 * allocated by this instance constructor). Afterwards it copies the data from the other packet in the same way
		 * used in the copy constructor.
		 * @param[in] other The instance to copy from
		 */
		Packet& operator=(const Packet& other);

		/**
		 * Get a pointer to the Packet's RawPacket
		 * @return A pointer to the Packet's RawPacket
		 */
		RawPacket* getRawPacket() const
		{
			return m_RawPacket;
		}

		/**
		 * Set a RawPacket and re-construct all packet layers
		 * @param[in] rawPacket Raw packet to set
		 * @param[in] freeRawPacket A flag indicating if the destructor should also call the raw packet destructor or
		 * not
		 * @param[in] parseUntil Parse the packet until it reaches this protocol. Can be useful for cases when you need
		 * to parse only up to a certain layer and want to avoid the performance impact and memory consumption of
		 * parsing the whole packet. Default value is ::UnknownProtocol which means don't take this parameter into
		 * account
		 * @param[in] parseUntilLayer Parse the packet until certain layer in OSI model. Can be useful for cases when
		 * you need to parse only up to a certain layer and want to avoid the performance impact and memory consumption
		 * of parsing the whole packet. Default value is ::OsiModelLayerUnknown which means don't take this parameter
		 * into account
		 */
		void setRawPacket(RawPacket* rawPacket, bool freeRawPacket, ProtocolTypeFamily parseUntil = UnknownProtocol,
		                  OsiModelLayer parseUntilLayer = OsiModelLayerUnknown);

		/**
		 * Get a pointer to the Packet's RawPacket in a read-only manner
		 * @return A pointer to the Packet's RawPacket
		 */
		RawPacket* getRawPacketReadOnly() const
		{
			return m_RawPacket;
		}

		/**
		 * Get a pointer to the first (lowest) layer in the packet
		 * @return A pointer to the first (lowest) layer in the packet
		 */
		Layer* getFirstLayer() const
		{
			return m_FirstLayer;
		}

		/**
		 * Get a pointer to the last (highest) layer in the packet
		 * @return A pointer to the last (highest) layer in the packet
		 */
		Layer* getLastLayer() const
		{
			return m_LastLayer;
		}

		/**
		 * Add a new layer as the last layer in the packet. This method gets a pointer to the new layer as a parameter
		 * and attaches it to the packet. Notice after calling this method the input layer is attached to the packet so
		 * every change you make in it affect the packet; Also it cannot be attached to other packets
		 * @param[in] newLayer A pointer to the new layer to be added to the packet
		 * @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct.  Default
		 * is false.
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool addLayer(Layer* newLayer, bool ownInPacket = false)
		{
			return insertLayer(m_LastLayer, newLayer, ownInPacket);
		}

		/**
		 * Insert a new layer after an existing layer in the packet. This method gets a pointer to the new layer as a
		 * parameter and attaches it to the packet. Notice after calling this method the input layer is attached to the
		 * packet so every change you make in it affect the packet; Also it cannot be attached to other packets
		 * @param[in] prevLayer A pointer to an existing layer in the packet which the new layer should followed by. If
		 * this layer isn't attached to a packet and error will be printed to log and false will be returned
		 * @param[in] newLayer A pointer to the new layer to be added to the packet
		 * @param[in] ownInPacket If true, Packet fully owns newLayer, including memory deletion upon destruct.  Default
		 * is false.
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool insertLayer(Layer* prevLayer, Layer* newLayer, bool ownInPacket = false);

		/**
		 * Remove an existing layer from the packet. The layer to removed is identified by its type (protocol). If the
		 * packet has multiple layers of the same type in the packet the user may specify the index of the layer to
		 * remove (the default index is 0 - remove the first layer of this type). If the layer was allocated during
		 * packet creation it will be deleted and any pointer to it will get invalid. However if the layer was allocated
		 * by the user and manually added to the packet it will simply get detached from the packet, meaning the pointer
		 * to it will stay valid and its data (that was removed from the packet) will be copied back to the layer. In
		 * that case it's the user's responsibility to delete the layer instance
		 * @param[in] layerType The layer type (protocol) to remove
		 * @param[in] index If there are multiple layers of the same type, indicate which instance to remove. The
		 * default value is 0, meaning remove the first layer of this type
		 * @return True if everything went well or false otherwise (an appropriate error log message will be printed in
		 * such cases)
		 */
		bool removeLayer(ProtocolType layerType, int index = 0);

		/**
		 * Remove the first layer in the packet. The layer will be deleted if it was allocated during packet creation,
		 * or detached if was allocated outside of the packet. Please refer to removeLayer() to get more info
		 * @return True if layer removed successfully, or false if removing the layer failed or if there are no layers
		 * in the packet. In any case of failure an appropriate error log message will be printed
		 */
		bool removeFirstLayer();

		/**
		 * Remove the last layer in the packet. The layer will be deleted if it was allocated during packet creation, or
		 * detached if was allocated outside of the packet. Please refer to removeLayer() to get more info
		 * @return True if layer removed successfully, or false if removing the layer failed or if there are no layers
		 * in the packet. In any case of failure an appropriate error log message will be printed
		 */
		bool removeLastLayer();

		/**
		 * Remove all layers that come after a certain layer. All layers removed will be deleted if they were allocated
		 * during packet creation or detached if were allocated outside of the packet, please refer to removeLayer() to
		 * get more info
		 * @param[in] layer A pointer to the layer to begin removing from. Please note this layer will not be removed,
		 * only the layers that come after it will be removed. Also, if removal of one layer failed, the method will
		 * return immediately and the following layers won't be deleted
		 * @return True if all layers were removed successfully, or false if failed to remove at least one layer. In any
		 * case of failure an appropriate error log message will be printed
		 */
		bool removeAllLayersAfter(Layer* layer);

		/**
		 * Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather separated
		 * from the packet - e.g it will be removed from the layer chain of the packet and its data will be copied from
		 * the packet buffer into an internal layer buffer. After a layer is detached, it can be added into another
		 * packet (but it's impossible to attach a layer to multiple packets in the same time). After layer is detached,
		 * it's the user's responsibility to delete it when it's not needed anymore
		 * @param[in] layerType The layer type (protocol) to detach from the packet
		 * @param[in] index If there are multiple layers of the same type, indicate which instance to detach. The
		 * default value is 0, meaning detach the first layer of this type
		 * @return A pointer to the detached layer or nullptr if detaching process failed. In any case of failure an
		 * appropriate error log message will be printed
		 */
		Layer* detachLayer(ProtocolType layerType, int index = 0);

		/**
		 * Detach a layer from the packet. Detaching means the layer instance will not be deleted, but rather separated
		 * from the packet - e.g it will be removed from the layer chain of the packet and its data will be copied from
		 * the packet buffer into an internal layer buffer. After a layer is detached, it can be added into another
		 * packet (but it's impossible to attach a layer to multiple packets at the same time). After layer is detached,
		 * it's the user's responsibility to delete it when it's not needed anymore
		 * @param[in] layer A pointer to the layer to detach
		 * @return True if the layer was detached successfully, or false if something went wrong. In any case of failure
		 * an appropriate error log message will be printed
		 */
		bool detachLayer(Layer* layer)
		{
			return removeLayer(layer, false);
		}

		/**
		 * Get a pointer to the layer of a certain type (protocol). This method goes through the layers and returns a
		 * layer that matches the give protocol type
		 * @param[in] layerType The layer type (protocol) to fetch
		 * @param[in] index If there are multiple layers of the same type, indicate which instance to fetch. The default
		 * value is 0, meaning fetch the first layer of this type
		 * @return A pointer to the layer or nullptr if no such layer was found
		 */
		Layer* getLayerOfType(ProtocolType layerType, int index = 0) const;

		/**
		 * A templated method to get a layer of a certain type (protocol). If no layer of such type is found, nullptr is
		 * returned
		 * @param[in] reverseOrder The optional parameter that indicates that the lookup should run in reverse order,
		 * the default value is false
		 * @return A pointer to the layer of the requested type, nullptr if not found
		 */
		template <class TLayer> TLayer* getLayerOfType(bool reverseOrder = false) const;

		/**
		 * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
		 * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
		 * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(3) will be
		 * returned If no layer of such type is found, nullptr is returned
		 * @param[in] startLayer A pointer to the layer to start search from
		 * @return A pointer to the layer of the requested type, nullptr if not found
		 */
		template <class TLayer> TLayer* getNextLayerOfType(Layer* startLayer) const;

		/**
		 * A templated method to get the first layer of a certain type (protocol), start searching from a certain layer.
		 * For example: if a packet looks like: EthLayer -> VlanLayer(1) -> VlanLayer(2) -> VlanLayer(3) -> IPv4Layer
		 * and the user put VlanLayer(2) as a parameter and wishes to search for a VlanLayer, VlanLayer(1) will be
		 * returned If no layer of such type is found, nullptr is returned
		 * @param[in] startLayer A pointer to the layer to start search from
		 * @return A pointer to the layer of the requested type, nullptr if not found
		 */
		template <class TLayer> TLayer* getPrevLayerOfType(Layer* startLayer) const;

		/**
		 * Check whether the packet contains a layer of a certain protocol
		 * @param[in] protocolType The protocol type to search
		 * @return True if the packet contains a layer of a certain protocol, false otherwise
		 */
		bool isPacketOfType(ProtocolType protocolType) const;

		/**
		 * Check whether the packet contains a layer of a certain protocol family
		 * @param[in] protocolTypeFamily The protocol type family to search
		 * @return True if the packet contains a layer of a certain protocol family, false otherwise
		 */
		bool isPacketOfType(ProtocolTypeFamily protocolTypeFamily) const;

		/**
		 * Each layer can have fields that can be calculate automatically from other fields using
		 * Layer#computeCalculateFields(). This method forces all layers to calculate these fields values
		 */
		void computeCalculateFields();

		/**
		 * Each layer can print a string representation of the layer most important data using Layer#toString(). This
		 * method aggregates this string from all layers and print it to a complete string containing all packet's
		 * relevant data
		 * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
		 * to false
		 * @return A string containing most relevant data from all layers (looks like the packet description in
		 * Wireshark)
		 */
		std::string toString(bool timeAsLocalTime = true) const;

		/**
		 * Similar to toString(), but instead of one string it outputs a list of strings, one string for every layer
		 * @param[out] result A string vector that will contain all strings
		 * @param[in] timeAsLocalTime Print time as local time or GMT. Default (true value) is local time, for GMT set
		 * to false
		 */
		void toStringList(std::vector<std::string>& result, bool timeAsLocalTime = true) const;

	private:
		void copyDataFrom(const Packet& other);

		void destructPacketData();

		bool extendLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToExtend);
		bool shortenLayer(Layer* layer, int offsetInLayer, size_t numOfBytesToShorten);

		void reallocateRawData(size_t newSize);

		bool removeLayer(Layer* layer, bool tryToDelete);

		std::string printPacketInfo(bool timeAsLocalTime) const;

		Layer* createFirstLayer(LinkLayerType linkType);
	};  // class Packet

	// implementation of inline methods

	template <class TLayer> TLayer* Packet::getLayerOfType(bool reverse) const
	{
		if (!reverse)
		{
			if (dynamic_cast<TLayer*>(getFirstLayer()) != nullptr)
				return dynamic_cast<TLayer*>(getFirstLayer());

			return getNextLayerOfType<TLayer>(getFirstLayer());
		}

		// lookup in reverse order
		if (dynamic_cast<TLayer*>(getLastLayer()) != nullptr)
			return dynamic_cast<TLayer*>(getLastLayer());

		return getPrevLayerOfType<TLayer>(getLastLayer());
	}

	template <class TLayer> TLayer* Packet::getNextLayerOfType(Layer* curLayer) const
	{
		if (curLayer == nullptr)
			return nullptr;

		curLayer = curLayer->getNextLayer();
		while ((curLayer != nullptr) && (dynamic_cast<TLayer*>(curLayer) == nullptr))
		{
			curLayer = curLayer->getNextLayer();
		}

		return dynamic_cast<TLayer*>(curLayer);
	}

	template <class TLayer> TLayer* Packet::getPrevLayerOfType(Layer* curLayer) const
	{
		if (curLayer == nullptr)
			return nullptr;

		curLayer = curLayer->getPrevLayer();
		while (curLayer != nullptr && dynamic_cast<TLayer*>(curLayer) == nullptr)
		{
			curLayer = curLayer->getPrevLayer();
		}

		return dynamic_cast<TLayer*>(curLayer);
	}

}  // namespace vanhooks::net

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::Packet& packet)
{
	os << packet.toString();
	return os;
}
// ---- end Packet.h ----

// ---- begin PayloadLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class PayloadLayer
	 * Represents a generic or unknown layer or a packet payload
	 */
	class PayloadLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		PayloadLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, GenericPayload)
		{}

		/**
		 * A constructor that allocates a new payload
		 * @param[in] data A raw buffer that will be used as a payload. This data will be copied to the layer
		 * @param[in] dataLen The raw buffer length
		 */
		PayloadLayer(const uint8_t* data, size_t dataLen);

		/**
		 * A constructor that allocates a new payload from an hex stream
		 * @param[in] payloadAsHexStream A string that represents an hex stream of the payload. For example:
		 * 0001080006040002842b2b774c56c0a80078000000000000c0a8. In order for the hex stream to be valid it has to
		 * contain valid hex chars only (which means, for example, that it can't begin with "0x") and it also has to
		 * have an even number of chars (each char represents one nibble). If the string is not a valid hex stream an
		 * error will be printed to log and the payload layer will be empty (no data)
		 */
		explicit PayloadLayer(const std::string& payloadAsHexStream);

		~PayloadLayer()
		{}

		/**
		 * Get a pointer to the payload data
		 * @return A pointer to the payload data
		 */
		uint8_t* getPayload() const
		{
			return m_Data;
		}

		/**
		 * Get the payload data length
		 * @return The payload data length in bytes
		 */
		size_t getPayloadLen() const
		{
			return m_DataLen;
		}

		// implement abstract methods

		/**
		 * Does nothing for this layer (PayloadLayer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return Payload data length in bytes
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields()
		{}

		/**
		 * Sets the payload of the PayloadLayer to the given pointer. This will resize (extend/shorten) the underlying
		 * packet respectively if there is one.
		 * @param[in] newPayload New payload that shall be set
		 * @param[in] newPayloadLength New length of payload
		 */
		void setPayload(const uint8_t* newPayload, size_t newPayloadLength);

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}
	};

}  // namespace vanhooks::net
// ---- end PayloadLayer.h ----

// ---- begin PacketTrailerLayer.h ----
/// @file


namespace vanhooks::net
{
	/**
	 * @class PacketTrailerLayer
	 * A class for representing packet tailer (a.k.a footer or padding) which refers to supplemental data placed at the
	 * end of a block of data being stored or transmitted, which may contain information for the handling of the data
	 * block, or just mark its end (taken from Wikipedia: https://en.wikipedia.org/wiki/Trailer_(computing) )
	 *
	 * There are various reasons for adding a packet trailer, one of the most famous is FCS (Frame check sequence) which
	 * refers to the extra error-detecting code added to a frame. Another usage is padding which means adding data to
	 * reach a minimum required packet length.
	 *
	 * Although this layer inherits from the Layer class, it is not a standard layer in the sense that it can't be
	 * constructed by the user. This layer may be only be constructed in the Packet class, in the process of parsing the
	 * packet and creating the layers; if at the end of the parsing process there is data left that is not allocated to
	 * any layer, it's assumed to be the packet trailer and an instance of this class is created. This means this layer
	 * can only exist as the last layer in a packet, if a packet trailer indeed exists.
	 *
	 * No layer can be added by the user after this layer (trying to do that will result with an error).
	 *
	 * This layer can be removed by the user or extended/shortened, as any layer.
	 *
	 * It also contains method to extract the trailer data
	 */
	class PacketTrailerLayer : public Layer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		PacketTrailerLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, PacketTrailer)
		{}

		~PacketTrailerLayer()
		{}

		/**
		 * Get a pointer to the trailer data
		 * @return A pointer to the trailer data
		 */
		uint8_t* getTrailerData() const
		{
			return m_Data;
		}

		/**
		 * @return Trailer data as hex string
		 */
		std::string getTrailerDataAsHexString() const;

		/**
		 * Get the trailer data length
		 * @return The trailer data length in bytes
		 */
		size_t getTrailerLen() const
		{
			return m_DataLen;
		}

		// implement abstract methods

		/**
		 * Does nothing for this layer (PacketTrailerLayer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return trailer data length in bytes
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
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
// ---- end PacketTrailerLayer.h ----

// ---- begin TLVData.h ----
#include <string.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @class TLVRecord
	 * A wrapper class for a Type-Length-Value (TLV) record. This class does not create or modify TLV records, but
	 * rather serves as a wrapper and provides useful methods for retrieving data from them. This class has several
	 * abstract methods that should be implemented in derived classes. These methods are for record length value
	 * calculation (the 'L' in TLV) which is implemented differently in different protocols
	 */
	template <typename TRecType, typename TRecLen> class TLVRecord
	{
	protected:
		/** A struct representing the TLV construct */
		struct TLVRawData
		{
			/** Record type */
			TRecType recordType;
			/** Record length in bytes */
			TRecLen recordLen;
			/** Record value (variable size) */
			uint8_t recordValue[];
		};

		TLVRawData* m_Data;

	public:
		/**
		 * A c'tor for this class that gets a pointer to the TLV record raw data (byte array)
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 */
		TLVRecord(uint8_t* recordRawData)
		{
			assign(recordRawData);
		}

		/**
		 * A copy c'tor for this class. This copy c'tor doesn't copy the TLV data, but only the pointer to it,
		 * which means that after calling it both the old and the new instance will point to the same TLV raw data
		 * @param[in] other The TLVRecord instance to copy from
		 */
		TLVRecord(const TLVRecord& other)
		{
			m_Data = other.m_Data;
		}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		virtual ~TLVRecord()
		{}

		/**
		 * Assign a pointer to the TLV record raw data (byte array)
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 */
		void assign(uint8_t* recordRawData)
		{
			m_Data = reinterpret_cast<TLVRawData*>(recordRawData);
		}

		/**
		 * Check if a pointer can be assigned to the TLV record data
		 * @param[in] recordRawData A pointer to the TLV record raw data
		 * @param[in] tlvDataLen The size of the TLV record raw data
		 * @return True if data is valid and can be assigned
		 */
		static bool canAssign(const uint8_t* recordRawData, size_t tlvDataLen)
		{
			return recordRawData != nullptr &&
			       tlvDataLen >= (sizeof(TLVRawData::recordType) + sizeof(TLVRawData::recordLen));
		}

		/**
		 * Overload of the assignment operator. This operator doesn't copy the TLV data, but rather copies the pointer
		 * to it, which means that after calling it both the old and the new instance will point to the same TLV raw
		 * data
		 * @param[in] other The TLVRecord instance to assign
		 */
		TLVRecord& operator=(const TLVRecord& other)
		{
			m_Data = other.m_Data;
			return *this;
		}

		/**
		 * Overload of the equality operator. Two record are equal if both of them point to the same data, or if they
		 * point to different data but their total size is equal and the raw data they both contain is similar.
		 * @param[in] rhs The object to compare to
		 * @return True if both objects are equal, false otherwise
		 */
		bool operator==(const TLVRecord& rhs) const
		{
			if (m_Data == rhs.m_Data)
				return true;

			if (getTotalSize() != rhs.getTotalSize())
				return false;

			if (isNull() || ((TLVRecord&)rhs).isNull())
				return false;

			return (memcmp(m_Data, rhs.m_Data, getTotalSize()) == 0);
		}

		/**
		 * Overload of the not equal operator.
		 * @param[in] rhs The object to compare to
		 * @return True if objects are not equal, false otherwise
		 */
		bool operator!=(const TLVRecord& rhs) const
		{
			return !operator==(rhs);
		}

		/**
		 * @return The type field of the record (the 'T' in __Type__-Length-Value)
		 */
		TRecType getType() const
		{
			if (m_Data == nullptr)
				return 0;

			return m_Data->recordType;
		}

		/**
		 * @return A pointer to the value of the record as byte array (the 'V' in Type-Length- __Value__)
		 */
		uint8_t* getValue() const
		{
			if (m_Data == nullptr)
				return nullptr;

			return m_Data->recordValue;
		}

		/**
		 * @return True if the TLV record raw data is nullptr, false otherwise
		 */
		bool isNull() const
		{
			return (m_Data == nullptr);
		}

		/**
		 * @return True if the TLV record raw data is not nullptr, false otherwise
		 */
		bool isNotNull() const
		{
			return (m_Data != nullptr);
		}

		/**
		 * @return A pointer to the TLV record raw data byte stream
		 */
		uint8_t* getRecordBasePtr() const
		{
			return (uint8_t*)m_Data;
		}

		/**
		 * Free the memory of the TLV record raw data
		 */
		void purgeRecordData()
		{
			if (!isNull())
			{
				delete[] m_Data;
				m_Data = nullptr;
			}
		}

		/**
		 * A templated method to retrieve the record data as a certain type T. For example, if record data is 4B long
		 * (integer) then this method should be used as getValueAs<int>() and it will return the record data as an
		 * integer.<BR> Notice this return value is a copy of the data, not a pointer to the actual data
		 * @param[in] offset The offset in the record data to start reading the value from. Useful for cases when you
		 * want to read some of the data that doesn't start at offset 0. This is an optional parameter and the default
		 * value is 0, meaning start reading the value at the beginning of the record data
		 * @return The record data as type T
		 */
		template <typename T> T getValueAs(size_t offset = 0) const
		{
			if (getDataSize() - offset < sizeof(T))
				return 0;

			T result;
			memcpy(&result, m_Data->recordValue + offset, sizeof(T));
			return result;
		}

		/**
		 * A templated method to copy data of type T into the TLV record data. For example: if record data is 4[Bytes]
		 * long use this method with \<int\> to set an integer value into the record data: setValue<int>(num)
		 * @param[in] newValue The value of type T to copy to the record data
		 * @param[in] valueOffset An optional parameter that specifies where to start setting the record data (default
		 * set to 0). For example: if record data is 20 bytes long and you only need to set the 4 last bytes as integer
		 * then use this method like this: setValue<int>(num, 16)
		 * @return True if value was set successfully or false if the size of T is larger than the record data size
		 */
		template <typename T> bool setValue(T newValue, int valueOffset = 0)
		{
			if (getDataSize() < sizeof(T))
				return false;

			memcpy(m_Data->recordValue + valueOffset, &newValue, sizeof(T));
			return true;
		}

		/**
		 * @return The total size of the TLV record (in bytes)
		 */
		virtual size_t getTotalSize() const = 0;

		/**
		 * @return The size of the record value (meaning the size of the 'V' part in TLV)
		 */
		virtual size_t getDataSize() const = 0;
	};

	/**
	 * @class TLVRecordReader
	 * A class for reading TLV records data out of a byte stream. This class contains helper methods for retrieving and
	 * counting TLV records. This is a template class that expects template argument class derived from TLVRecord.
	 */
	template <typename TLVRecordType> class TLVRecordReader
	{
	private:
		mutable size_t m_RecordCount;

	public:
		/**
		 * A default c'tor for this class
		 */
		TLVRecordReader()
		{
			m_RecordCount = (size_t)-1;
		}

		/**
		 * A default copy c'tor for this class
		 */
		TLVRecordReader(const TLVRecordReader& other)
		{
			m_RecordCount = other.m_RecordCount;
		}

		/**
		 * A d'tor for this class which currently does nothing
		 */
		virtual ~TLVRecordReader()
		{}

		/**
		 * Overload of the assignment operator for this class
		 * @param[in] other The TLVRecordReader instance to assign
		 */
		TLVRecordReader& operator=(const TLVRecordReader& other)
		{
			m_RecordCount = other.m_RecordCount;
			return *this;
		}

		/**
		 * Get the first TLV record out of a byte stream
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return An instance of type TLVRecordType that contains the first TLV record. If tlvDataBasePtr is nullptr or
		 * tlvDataLen is zero the returned TLVRecordType instance will be logically null, meaning
		 * TLVRecordType.isNull() will return true
		 */
		TLVRecordType getFirstTLVRecord(uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			TLVRecordType resRec(nullptr);  // for NRVO optimization
			if (!TLVRecordType::canAssign(tlvDataBasePtr, tlvDataLen))
				return resRec;

			resRec.assign(tlvDataBasePtr);
			// resRec pointer is out-bounds of the TLV records memory
			if (resRec.getRecordBasePtr() + resRec.getTotalSize() > tlvDataBasePtr + tlvDataLen)
				resRec.assign(nullptr);

			// check if there are records at all and the total size is not zero
			if (!resRec.isNull() && (tlvDataLen == 0 || resRec.getTotalSize() == 0))
				resRec.assign(nullptr);

			return resRec;
		}

		/**
		 * Get a TLV record that follows a given TLV record in a byte stream
		 * @param[in] record A given TLV record
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return An instance of type TLVRecordType that wraps the record following the record given as input. If the
		 * input record.isNull() is true or if the next record is out of bounds of the byte stream, a logical null
		 * instance of TLVRecordType will be returned, meaning TLVRecordType.isNull() will return true
		 */
		TLVRecordType getNextTLVRecord(TLVRecordType& record, const uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			TLVRecordType resRec(nullptr);  // for NRVO optimization

			if (record.isNull())
				return resRec;

			if (!TLVRecordType::canAssign(record.getRecordBasePtr() + record.getTotalSize(),
			                              tlvDataBasePtr - record.getRecordBasePtr() + tlvDataLen -
			                                  record.getTotalSize()))
				return resRec;

			resRec.assign(record.getRecordBasePtr() + record.getTotalSize());

			if (resRec.getTotalSize() == 0)
				resRec.assign(nullptr);

			// resRec pointer is out-bounds of the TLV records memory
			if ((resRec.getRecordBasePtr() - tlvDataBasePtr) < 0)
				resRec.assign(nullptr);

			// resRec pointer is out-bounds of the TLV records memory
			if (!resRec.isNull() && resRec.getRecordBasePtr() + resRec.getTotalSize() > tlvDataBasePtr + tlvDataLen)
				resRec.assign(nullptr);

			return resRec;
		}

		/**
		 * Search for the first TLV record that corresponds to a given record type (the 'T' in __Type__-Length-Value)
		 * @param[in] recordType The record type to search for
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return An instance of type TLVRecordType that contains the result record. If record was not found a logical
		 * null instance of TLVRecordType will be returned, meaning TLVRecordType.isNull() will return true
		 */
		TLVRecordType getTLVRecord(uint32_t recordType, uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			TLVRecordType curRec = getFirstTLVRecord(tlvDataBasePtr, tlvDataLen);
			while (!curRec.isNull())
			{
				if (curRec.getType() == recordType)
				{
					return curRec;
				}

				curRec = getNextTLVRecord(curRec, tlvDataBasePtr, tlvDataLen);
			}

			curRec.assign(nullptr);
			return curRec;  // for NRVO optimization
		}

		/**
		 * Get the TLV record count in a given TLV data byte stream. For efficiency purposes the count is being cached
		 * so only the first call to this method will go over all the TLV records, while all consequent calls will
		 * return the cached number. This implies that if there is a change in the number of records, it's the user's
		 * responsibility to call changeTLVRecordCount() with the record count change
		 * @param[in] tlvDataBasePtr A pointer to the TLV data byte stream
		 * @param[in] tlvDataLen The TLV data byte stream length
		 * @return The TLV record count
		 */
		size_t getTLVRecordCount(uint8_t* tlvDataBasePtr, size_t tlvDataLen) const
		{
			if (m_RecordCount != (size_t)-1)
				return m_RecordCount;

			m_RecordCount = 0;
			TLVRecordType curRec = getFirstTLVRecord(tlvDataBasePtr, tlvDataLen);
			while (!curRec.isNull())
			{
				m_RecordCount++;
				curRec = getNextTLVRecord(curRec, tlvDataBasePtr, tlvDataLen);
			}

			return m_RecordCount;
		}

		/**
		 * As described in getTLVRecordCount(), the TLV record count is being cached for efficiency purposes. So if the
		 * number of TLV records change, it's the user's responsibility to call this method with the number of TLV
		 * records being added or removed. If records were added the change should be a positive number, or a negative
		 * number if records were removed
		 * @param[in] changedBy Number of records that were added or removed
		 */
		void changeTLVRecordCount(int changedBy)
		{
			if (m_RecordCount != (size_t)-1)
				m_RecordCount += changedBy;
		}
	};

	/**
	 * @class TLVRecordBuilder
	 * A base class for building Type-Length-Value (TLV) records. This builder receives the record parameters in its
	 * c'tor, builds the record raw buffer and provides a method to build a TLVRecord object out of it. Please notice
	 * this is a base class that lacks the capability of actually building TLVRecord objects and also cannot be
	 * instantiated. The reason for that is that different protocols build TLV records in different ways, so these
	 * missing capabilities will be implemented by the derived classes which are specific to each protocol. This class
	 * only provides the common infrastructure that will be used by them
	 */
	class TLVRecordBuilder
	{
	protected:
		TLVRecordBuilder();

		TLVRecordBuilder(uint32_t recType, const uint8_t* recValue, uint8_t recValueLen);

		TLVRecordBuilder(uint32_t recType, uint8_t recValue);

		TLVRecordBuilder(uint32_t recType, uint16_t recValue);

		TLVRecordBuilder(uint32_t recType, uint32_t recValue);

		TLVRecordBuilder(uint32_t recType, const IPv4Address& recValue);

		TLVRecordBuilder(uint32_t recType, const std::string& recValue, bool valueIsHexString = false);

		TLVRecordBuilder(const TLVRecordBuilder& other);

		TLVRecordBuilder& operator=(const TLVRecordBuilder& other);

		virtual ~TLVRecordBuilder();

		void init(uint32_t recType, const uint8_t* recValue, size_t recValueLen);

		uint8_t* m_RecValue;
		size_t m_RecValueLen;
		uint32_t m_RecType;

	private:
		void copyData(const TLVRecordBuilder& other);
	};
}  // namespace vanhooks::net
// ---- end TLVData.h ----

// ---- begin PacketUtils.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * A struct that represent a single buffer
	 */
	template <typename T> struct ScalarBuffer
	{
		/**
		 * The pointer to the buffer
		 */
		T* buffer;

		/**
		 * Buffer length
		 */
		size_t len;
	};

	/**
	 * Computes the checksum for a vector of buffers
	 * @param[in] vec The vector of buffers
	 * @param[in] vecSize Number of ScalarBuffers in vector
	 * @return The checksum result
	 */
	uint16_t computeChecksum(ScalarBuffer<uint16_t> vec[], size_t vecSize);

	/**
	 * Computes the checksum for Pseudo header
	 * @param[in] dataPtr Data pointer
	 * @param[in] dataLen Data length
	 * @param[in] ipAddrType IP address type(IPv4/IPv6) type @ref IPAddress::AddressType
	 * @param[in] protocolType Current protocol type @ref IPProtocolTypes
	 * @param[in] srcIPAddress Source IP Address
	 * @param[in] dstIPAddress Destination IP Address
	 * @return The checksum result
	 */
	uint16_t computePseudoHdrChecksum(uint8_t* dataPtr, size_t dataLen, IPAddress::AddressType ipAddrType,
	                                  uint8_t protocolType, IPAddress srcIPAddress, IPAddress dstIPAddress);

	/**
	 * Computes Fowler-Noll-Vo (FNV-1) 32bit hash function on an array of byte buffers. The hash is calculated on each
	 * byte in each byte buffer, as if all byte buffers were one long byte buffer
	 * @param[in] vec An array of byte buffers (ScalarBuffer of type uint8_t)
	 * @param[in] vecSize The length of vec
	 * @return The 32bit hash value
	 */
	uint32_t fnvHash(ScalarBuffer<uint8_t> vec[], size_t vecSize);

	/**
	 * Computes Fowler-Noll-Vo (FNV-1) 32bit hash function on a byte buffer
	 * @param[in] buffer The byte buffer
	 * @param[in] bufSize The size of the byte buffer
	 * @return The 32bit hash value
	 */
	uint32_t fnvHash(uint8_t* buffer, size_t bufSize);

	/**
	 * A method that is given a packet and calculates a hash value by the packet's 5-tuple. Supports IPv4, IPv6,
	 * TCP and UDP. For packets which doesn't have 5-tuple (for example: packets which aren't IPv4/6 or aren't
	 * TCP/UDP) the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @param[in] directionUnique Make hash value unique for each direction
	 * @return The hash value calculated for this packet or 0 if the packet doesn't contain 5-tuple
	 */
	uint32_t hash5Tuple(Packet* packet, bool const& directionUnique = false);

	/**
	 * A method that is given a packet and calculates a hash value by the packet's 2-tuple (IP src + IP dst). Supports
	 * IPv4 and IPv6. For packets which aren't IPv4/6 the value of 0 will be returned
	 * @param[in] packet The packet to calculate hash for
	 * @return The hash value calculated for this packet or 0 if the packet isn't IPv4/6
	 */
	uint32_t hash2Tuple(Packet* packet);

}  // namespace vanhooks::net
// ---- end PacketUtils.h ----

