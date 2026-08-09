#pragma once

// ===== Consolidated header: IndustrialLayers.h =====
// Merges: CotpLayer, TpktLayer, S7CommLayer, SomeIpLayer, SomeIpSdLayer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "L2Layers.h"
#include "PacketCore.h"
#include "Common.h"

// ---- begin CotpLayer.h ----
namespace vanhooks::net
{

/**
 * @struct cotphdr
 * Represents a COTP protocol header
 */
#pragma pack(push, 1)
	typedef struct
	{
		/** length */
		uint8_t length;
		/** PDU type identifier */
		uint8_t pduType;
		/** TPDU number sequence*/
		uint8_t tpduNumber;
	} cotphdr;
#pragma pack(pop)

	/**
	 * @class CotpLayer
	 * Represents a COTP (Connection Oriented Transport Protocol)
	 */
	class CotpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref cotphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		CotpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, COTP)
		{}

		/**
		 * A constructor that allocates a new COTP header
		 * @param[in] tpduNumber Protocol TPDU number
		 */
		explicit CotpLayer(uint8_t tpduNumber);

		virtual ~CotpLayer()
		{}

		/**
		 * @return COTP length
		 */
		uint8_t getLength() const;

		/**
		 * @return COTP PDU type
		 */
		uint8_t getPduType() const;

		/**
		 * @return COTP TPDU number
		 */
		uint8_t getTpduNumber() const;

		/**
		 * @return Size of @ref cotphdr
		 */
		size_t getHeaderLen() const override
		{
			return sizeof(cotphdr);
		}

		/**
		 * Set the value of the length
		 * @param[in] length The value of the length
		 */
		void setLength(uint8_t length) const;

		/**
		 * Set the value of the version
		 * @param[in] pduType The number of the PDU type
		 */
		void setPduType(uint8_t pduType) const;

		/**
		 * Set the value of the version
		 * @param[in] tpduNumber The value of the TPDU number
		 */
		void setTpduNumber(uint8_t tpduNumber) const;

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override
		{}

		/**
		 * Currently parses the rest of the packet as a S7COMM or generic payload (PayloadLayer)
		 */
		void parseNextLayer() override;

		/**
		 * A static method that takes a byte array and detects whether it is a COTP
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data looks like a valid COTP layer
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
		cotphdr* getCotpHeader() const
		{
			return (cotphdr*)m_Data;
		}
	};

}  // namespace vanhooks::net
// ---- end CotpLayer.h ----

// ---- begin TpktLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct tpkthdr
	 * Represents a TPKT protocol header
	 */
#pragma pack(push, 1)
	struct tpkthdr
	{
		/** message version */
		uint8_t version;
		/** message reserved */
		uint8_t reserved;
		/** message length */
		uint16_t length;
	};
#pragma pack(pop)

	/**
	 * @class TpktLayer
	 * Represents a TPKT (Transport Service on top of the TCP) protocol layer
	 */
	class TpktLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref tpkthdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		TpktLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, TPKT)
		{}

		/**
		 * A constructor that allocates a new TPKT header
		 * @param[in] version Protocol version number
		 * @param[in] length Packet length
		 */
		TpktLayer(uint8_t version, uint16_t length);

		virtual ~TpktLayer()
		{}

		/**
		 * @return TPKT reserved
		 */
		uint8_t getReserved() const;

		/**
		 * @return TPKT version
		 */
		uint8_t getVersion() const;

		/**
		 * @return TPKT length
		 */
		uint16_t getLength() const;

		/**
		 * Set the value of the version
		 * @param[in] version The value of the version
		 */
		void setVersion(uint8_t version) const;

		/**
		 * Set the value of the length
		 * @param[in] length The value of the length
		 */
		void setLength(uint16_t length) const;

		/**
		 * @return Size of @ref tpkthdr
		 */
		size_t getHeaderLen() const override
		{
			return sizeof(tpkthdr);
		}

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() override
		{}

		/**
		 * Currently parses the rest of the packet as a COTP protocol or generic payload (PayloadLayer)
		 */
		void parseNextLayer() override;

		/**
		 * A static method that checks whether a source or dest port match those associated with the TPKT protocol
		 * @param[in] portSrc Source port number to check
		 * @param[in] portDst Dest port number to check
		 * @return True if the source or dest port match those associated with the TPKT protocol
		 */
		static bool isTpktPort(uint16_t portSrc, uint16_t portDst)
		{
			return portSrc == 102 || portDst == 102;
		}

		/**
		 * A static method that takes a byte array and detects whether it is a TPKT message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data size is greater or equal than the size of tpkthdr
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize)
		{
			return data && dataSize >= sizeof(tpkthdr);
		}

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelTransportLayer;
		}

	private:
		/**
		 * Get a pointer to the TPKT header. Data can be retrieved through the
		 * other methods of this layer. Notice the return value points directly to the data, so every change will change
		 * the actual packet data
		 * @return A pointer to the @ref tpkthdr
		 */
		tpkthdr* getTpktHeader() const
		{
			return (tpkthdr*)m_Data;
		}
	};

}  // namespace vanhooks::net
// ---- end TpktLayer.h ----

// ---- begin S7CommLayer.h ----
namespace vanhooks::net
{
/**
 * @struct s7commhdr
 * Represents a S7COMM protocol header
 */
#pragma pack(push, 1)
	typedef struct
	{
		/** protocol id */
		uint8_t protocolId;
		/** message type */
		uint8_t msgType;
		/** redundancy identification (reserved) */
		uint16_t reserved;
		/** protocol data unit reference */
		uint16_t pduRef;
		/** parameter length */
		uint16_t paramLength;
		/** data length */
		uint16_t dataLength;
	} s7commhdr;
#pragma pack(pop)

/**
 * @struct s7comm_ack_data_hdr
 * Represents a S7COMM protocol header with Ack-Data header
 */
#pragma pack(push, 1)
	struct s7comm_ack_data_hdr : s7commhdr
	{
		/** error class */
		uint8_t errorClass;
		/** error code */
		uint8_t errorCode;
	};
#pragma pack(pop)

	/**
	 * @class S7CommParameter
	 * Represents a S7COMM (S7 Communication) protocol Parameter
	 */
	class S7CommParameter
	{
		friend class S7CommLayer;

	public:
		S7CommParameter()
		{}

		virtual ~S7CommParameter()
		{}

		/**
		 * @return The data of the Parameter
		 */
		uint8_t* getData() const
		{
			return m_Data;
		}
		/**
		 * @return The length of the Parameter data
		 */
		size_t getDataLength() const
		{
			return m_DataLen;
		}

	private:
		S7CommParameter(uint8_t* data, size_t dataLen) : m_Data(data), m_DataLen(dataLen)
		{}
		uint8_t* m_Data;
		size_t m_DataLen;
	};
	/**
	 * @class S7CommLayer
	 * Represents a S7COMM (S7 Communication) protocol
	 */
	class S7CommLayer : public Layer
	{
	public:
		/**
		 * A constructor that allocates a new S7comm header
		 * @param[in] msgType The general type of the message
		 * @param[in] pduRef Link responses to their requests
		 * @param[in] paramLength The length of the parameter field
		 * @param[in] dataLength The length of the data field
		 * @param[in] errorClass The value of the error class
		 * @param[in] errorCode The value of the error code
		 */
		S7CommLayer(uint8_t msgType, uint16_t pduRef, uint16_t paramLength, uint16_t dataLength, uint8_t errorClass = 0,
		            uint8_t errorCode = 0);

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref s7commhdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		S7CommLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, S7COMM)
		{
			m_Parameter = nullptr;
		}

		virtual ~S7CommLayer()
		{
			if (m_Parameter)
				delete m_Parameter;
		}

		/**
		 * @return S7comm protocol id
		 */
		uint8_t getProtocolId() const;

		/**
		 * @return S7comm message type
		 */
		uint8_t getMsgType() const;

		/**
		 * @return S7comm PDU ref
		 */
		uint16_t getPduRef() const;

		/**
		 * @return S7comm parameter length
		 */
		uint16_t getParamLength() const;

		/**
		 * @return S7comm data length
		 */
		uint16_t getDataLength() const;

		/**
		 * @return S7comm error code
		 */
		uint8_t getErrorCode() const;

		/**
		 * @return S7comm error class
		 */
		uint8_t getErrorClass() const;

		/**
		 * @return S7comm parameter
		 */
		const S7CommParameter* getParameter();

		/**
		 * Set the value of the message type
		 * @param[in] msgType The value of the message type
		 */
		void setMsgType(uint8_t msgType) const;

		/**
		 * Set the value of the PDU ref
		 * @param[in] pduRef The value of the PDU ref
		 */
		void setPduRef(uint16_t pduRef) const;

		/**
		 * Set the value of the error code
		 * @param[in] errorCode The value of the error code
		 */
		void setErrorCode(uint8_t errorCode) const;
		/**
		 * Set the value of the error class
		 * @param[in] errorClass The value of the error class
		 */
		void setErrorClass(uint8_t errorClass) const;

		/**
		 * @return Size of S7CommLayer
		 */
		size_t getHeaderLen() const override
		{
			return m_DataLen;
		}

		/**
		 * Does nothing for this layer (S7CommLayer is always last)
		 */
		void computeCalculateFields() override
		{}

		/**
		 * Does nothing for this layer (S7CommLayer is always last)
		 */
		void parseNextLayer() override
		{}

		/**
		 * A static method that takes a byte array and detects whether it is a S7COMM
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data looks like a valid S7COMM layer
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		std::string toString() const override;

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

	private:
		s7commhdr* getS7commHeader() const
		{
			return (s7commhdr*)m_Data;
		}

		s7comm_ack_data_hdr* getS7commAckDataHeader() const
		{
			if (getS7commHeader()->msgType == 0x03)
			{
				return (s7comm_ack_data_hdr*)m_Data;
			}
			return nullptr;
		}

		size_t getS7commHeaderLength() const;

		S7CommParameter* m_Parameter;
	};

}  // namespace vanhooks::net
// ---- end S7CommLayer.h ----

// ---- begin SomeIpLayer.h ----
#include <unordered_set>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class SomeIpLayer
	 * Represents a SOME/IP protocol layer
	 */
	class SomeIpLayer : public Layer
	{
	public:
		/**
		 * SOME/IP message types
		 */
		enum class MsgType : uint8_t
		{
			/** A request expecting a response (even void) */
			REQUEST = 0x00,
			/** Acknowledgment for REQUEST(optional) */
			REQUEST_ACK = 0x40,
			/** A fire&forget request */
			REQUEST_NO_RETURN = 0x01,
			/** Acknowledgment for REQUEST_NO_RETURN(informational) */
			REQUEST_NO_RETURN_ACK = 0x41,
			/** A request of a notification expecting no response */
			NOTIFICATION = 0x02,
			/** Acknowledgment for NOTIFICATION(informational) */
			NOTIFICATION_ACK = 0x42,
			/** The response message */
			RESPONSE = 0x80,
			/** The Acknowledgment for RESPONSE(informational) */
			RESPONSE_ACK = 0xC0,
			/** The response containing an error */
			ERRORS = 0x81,
			/** Acknowledgment for ERROR(informational) */
			ERROR_ACK = 0xC1,
			/** A TP request expecting a response (even void) */
			TP_REQUEST = 0x20,
			/** A TP fire&forget request */
			TP_REQUEST_NO_RETURN = 0x21,
			/** A TP request of a notification/event callback expecting no response */
			TP_NOTIFICATION = 0x22,
			/** The TP response message */
			TP_RESPONSE = 0xa0,
			/** The TP response containing an error */
			TP_ERROR = 0xa1,
		};

		/**
		 * @struct someiphdr
		 * Represents a SOME/IP protocol header
		 */
#pragma pack(push, 1)
		struct someiphdr
		{
			/** Service ID */
			uint16_t serviceID;
			/** Method ID. Most significant bit 0 when E2E communication. 1 when SOME/IP event */
			uint16_t methodID;
			/** Length. Also covers payload. Excludes serviceID, methodID and length field itself */
			uint32_t length;
			/** Client ID */
			uint16_t clientID;
			/** Session ID */
			uint16_t sessionID;
			/** Protocol Version */
			uint8_t protocolVersion;
			/** Interface Version */
			uint8_t interfaceVersion;
			/** Message Type */
			uint8_t msgType;
			/** Return Code */
			uint8_t returnCode;
		};
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to someiphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SomeIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, SomeIP)
		{}

		/**
		 * Construct a new layer object
		 * @param[in] serviceID Service ID
		 * @param[in] methodID Method ID
		 * @param[in] clientID Client ID
		 * @param[in] sessionID Session ID
		 * @param[in] interfaceVersion Interface Version
		 * @param[in] type Type of the message
		 * @param[in] returnCode Return Code
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * holds the reference to a data buffer. This option can be used to reduce the number of copies to generate
		 * packets.
		 */
		SomeIpLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
		            uint8_t interfaceVersion, MsgType type, uint8_t returnCode, const uint8_t* const data = nullptr,
		            size_t dataLen = 0);

		/**
		 * Destroy the layer object
		 */
		~SomeIpLayer()
		{}

		/**
		 * A static method that creates a SOME/IP or SOME/IP-TP layer from packet raw data. Returns PayloadLayer if data
		 * is not valid.
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return Layer* A newly allocated layer
		 */
		static Layer* parseSomeIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Get a pointer to the basic SOME/IP header. Notice this points directly to the data, so every change will
		 * change the actual packet data
		 * @return A pointer to the someiphdr
		 */
		someiphdr* getSomeIpHeader() const
		{
			return (someiphdr*)m_Data;
		}

		/**
		 * Checks if given port is a SOME/IP protocol port (only Service Discovery ports are checked for now)
		 * @param[in] port Port to check
		 * @return true if SOME/IP protocol port, false if not
		 */
		static bool isSomeIpPort(uint16_t port);

		/**
		 * Adds port to a list of ports where pcap checks for SOME/IP communication.
		 * Each port must be removed at the end in order to have no memory leak.
		 * @param[in] port Port to add
		 */
		static void addSomeIpPort(uint16_t port);

		/**
		 * Removes port from a list of ports where pcap checks for SOME/IP communication.
		 * @param[in] port Port to remove
		 */
		static void removeSomeIpPort(uint16_t port);

		/**
		 * Removes all ports from a list of ports where pcap checks for SOME/IP communication.
		 */
		static void removeAllSomeIpPorts();

		/**
		 * Get the messageID
		 * @return uint32_t returned in host endian
		 */
		uint32_t getMessageID() const;

		/**
		 * Set the Message ID
		 * @param[in] messageID messageID to set
		 */
		void setMessageID(uint32_t messageID);

		/**
		 * Get the serviceID
		 * @return uint16_t returned in host endian
		 */
		uint16_t getServiceID() const;

		/**
		 * Set the Service ID
		 * @param[in] serviceID serviceID to set
		 */
		void setServiceID(uint16_t serviceID);

		/**
		 * Get the methodID
		 * @return uint16_t returned in host endian
		 */
		uint16_t getMethodID() const;

		/**
		 * Set the Method ID
		 * @param[in] methodID methodID to set
		 */
		void setMethodID(uint16_t methodID);

		/**
		 * Get the Length Field of the SOME/IP header
		 * @return uint32_t The length field of the SOME/IP header
		 */
		uint32_t getLengthField() const;

		/**
		 * Get the requestID
		 * @return uint32_t returned in host endian
		 */
		uint32_t getRequestID() const;

		/**
		 * Set the Request ID
		 * @param[in] requestID requestID to set
		 */
		void setRequestID(uint32_t requestID);

		/**
		 * Get the sessionID
		 * @return uint16_t returned in host endian
		 */
		uint16_t getSessionID() const;

		/**
		 * Set the Session ID
		 * @param[in] sessionID sessionID to set
		 */
		void setSessionID(uint16_t sessionID);

		/**
		 * Get the clientID
		 * @return uint16_t returned in host endian
		 */
		uint16_t getClientID() const;

		/**
		 * Set the Client ID
		 * @param[in] clientID clientID to set
		 */
		void setClientID(uint16_t clientID);

		/**
		 * Get the protocolVersion
		 * @return uint8_t
		 */
		uint8_t getProtocolVersion() const;

		/**
		 * Set the Protocol Version
		 * @param[in] version version to set
		 */
		void setProtocolVersion(uint8_t version);

		/**
		 * Get the interfaceVersion
		 * @return uint8_t
		 */
		uint8_t getInterfaceVersion() const;

		/**
		 * Set the Interface Version
		 * @param[in] version version to set
		 */
		void setInterfaceVersion(uint8_t version);

		/**
		 * Get the message type
		 * @return uint8_t
		 */
		uint8_t getMessageTypeAsInt() const;

		/**
		 * Get the message type
		 * @return SomeIpLayer::MsgType
		 */
		SomeIpLayer::MsgType getMessageType() const;

		/**
		 * Set the Message Type
		 * @param[in] type Type to set
		 */
		void setMessageType(MsgType type);

		/**
		 * Set the Message Type
		 * @param[in] type Type to set
		 */
		void setMessageType(uint8_t type);

		/**
		 * Get the returnCode
		 * @return uint8_t
		 */
		uint8_t getReturnCode() const;

		/**
		 * Set the returnCode
		 * @param[in] returnCode ReturnCode to set
		 */
		void setReturnCode(uint8_t returnCode);

		/**
		 * Set the length field of the SOME/IP header
		 * @param[in] payloadLength Length of the payload
		 */
		void setPayloadLength(uint32_t payloadLength);

		/**
		 * @return A pointer for the layer payload, meaning the first byte after the header
		 */
		uint8_t* getPduPayload() const
		{
			return m_Data + getSomeIpHeaderLen();
		}

		/**
		 * @return The size in bytes of the payload
		 */
		size_t getPduPayloadSize() const
		{
			return getHeaderLen() - getSomeIpHeaderLen();
		}

		/**
		 * Get the Length of the SOME/IP header inc payload
		 * @return size_t
		 */
		size_t getHeaderLen() const
		{
			return sizeof(uint32_t) * 2 + getLengthField();
		}

		/**
		 * Does nothing for this layer
		 */
		virtual void computeCalculateFields()
		{}

		/**
		 * Identifies the following next layers: SomeIpLayer, SomeIpTpLayer, SomeIpSdLayer. Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return The string representation of the SOME/IP layer
		 */
		virtual std::string toString() const;

		/**
		 * @return The OSI model layer of this layer
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

	protected:
		SomeIpLayer()
		{}

	private:
		static const uint8_t SOMEIP_PROTOCOL_VERSION = 1;
		virtual size_t getSomeIpHeaderLen() const
		{
			return sizeof(someiphdr);
		}

		/* Using unordered_set since insertion and search should be almost constant time */
		static std::unordered_set<uint16_t> m_SomeIpPorts;
	};

	/**
	 * @class SomeIpTpLayer
	 * Represents an SOME/IP Transport Protocol Layer
	 */
	class SomeIpTpLayer : public SomeIpLayer
	{
	public:
		/**
		 * @struct someiptphdr
		 * Represents an SOME/IP-TP protocol header.
		 */
#pragma pack(push, 1)
		struct someiptphdr : someiphdr
		{
			/** Contains the offset and the more segments flag. 28 bit offset field measured in 16 bytes + 3 bit
			 * reserved + 1 bit more segments flag */
			uint32_t offsetAndFlag;
		};
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to @ref someiptphdr)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SomeIpTpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SomeIpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A constructor that creates empty layer and sets values
		 * @param[in] serviceID Service ID
		 * @param[in] methodID Method ID
		 * @param[in] clientID Client ID
		 * @param[in] sessionID Session ID
		 * @param[in] interfaceVersion Interface Version
		 * @param[in] type Type of the message
		 * @param[in] returnCode Return Code
		 * @param[in] offset Offset indicating the data offset in increments of 16 bytes
		 * @param[in] moreSegmentsFlag Flag indicating whether more SOME/IP-TP Packets will follow
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 */
		SomeIpTpLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
		              uint8_t interfaceVersion, MsgType type, uint8_t returnCode, uint32_t offset,
		              bool moreSegmentsFlag, const uint8_t* const data = nullptr, size_t dataLen = 0);

		/**
		 * Destroy the layer object
		 */
		~SomeIpTpLayer()
		{}

		/**
		 * Get a pointer to the basic SOME/IP-TP header. Notice this points directly to the data, so every change will
		 * change the actual packet data
		 * @return A pointer to the @ref someiptphdr
		 */
		someiptphdr* getSomeIpTpHeader() const
		{
			return (someiptphdr*)m_Data;
		}

		/**
		 * Get the Offset. Offset is returned in multiple of 16 bytes.
		 * @return The offset value
		 */
		uint32_t getOffset() const;

		/**
		 * Set the Offset. Already has to be in multiples of 16 bytes.
		 * If 32 bytes have already been transmitted, the offset has to be set to 2.
		 * @param[in] offset Offset to set. Already has to be in multiples of 16 bytes.
		 */
		void setOffset(uint32_t offset);

		/**
		 * Get the More Segments Flag
		 * @return true if the More Segments Flag is set, false if it is not set
		 */
		bool getMoreSegmentsFlag() const;

		/**
		 * Set the More Segments Flag
		 * @param[in] flag True if the More Segments Flag shall be set, false for resetting
		 */
		void setMoreSegmentsFlag(bool flag);

		/**
		 * Sets the message type in this layer with enabling the TP flag
		 */
		void computeCalculateFields();

		/**
		 * @return The string representation of the SOME/IP-TP layer
		 */
		std::string toString() const;

	private:
		static const uint32_t SOMEIP_TP_MORE_FLAG_MASK = 0x01;
		static const uint32_t SOMEIP_TP_OFFSET_MASK = 0xFFFFFFF0;

		size_t getSomeIpHeaderLen() const
		{
			return sizeof(someiptphdr);
		}

		static uint8_t setTpFlag(uint8_t messageType);
	};

}  // namespace vanhooks::net
// ---- end SomeIpLayer.h ----

// ---- begin SomeIpSdLayer.h ----
#include <cstring>
#include <iterator>
#include <unordered_map>
#include <memory>
#include <stdexcept>
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * Types of protocols that can be referenced in SOME/IP-SD
	 */
	enum SomeIpSdProtocolType : uint8_t
	{
		/** TCP */
		SD_TCP = 0x06,
		/** UDP */
		SD_UDP = 0x11
	};

	class SomeIpSdLayer;

	/**
	 * @class SomeIpSdOption
	 * Base class of the SOME/IP-SD options. Cannot be instantiated.
	 */
	class SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/**
		 * Types of options currently available for the SOME/IP-SD protocol
		 */
		enum class OptionType : uint8_t
		{
			/** Unknown Option Type */
			Unknown = 0x00,
			/** Configuration Option */
			ConfigurationString = 0x01,
			/** Load Balancing Option */
			LoadBalancing = 0x02,
			/** IPv4 Endpoint Option */
			IPv4Endpoint = 0x04,
			/** IPv6 Endpoint Option */
			IPv6Endpoint = 0x06,
			/** IPv4 Multicast Option */
			IPv4Multicast = 0x14,
			/** IPv6 Multicast Option */
			IPv6Multicast = 0x16,
			/** IPv4 SD Endpoint Option */
			IPv4SdEndpoint = 0x24,
			/** IPv6 SD Endpoint Option */
			IPv6SdEndpoint = 0x26
		};

		/**
		 * @struct someipsdhdroptionsbase
		 * Represents the common base for SOME/IP-SD header options
		 */
#pragma pack(push, 1)
		struct someipsdhdroptionsbase
		{
			/** Length - excluding the 16 bit Length field and the 8 bit type flag */
			uint16_t length;
			/** Type */
			uint8_t type;
			/** Reserved */
			uint8_t reserved;
		};
#pragma pack(pop)

		/**
		 * Destroy the SOME/IP-SD Option object and delete allocated data if it has been allocated by a constructor
		 */
		virtual ~SomeIpSdOption();

		/**
		 * Get the Option Type
		 * @return OptionType
		 */
		OptionType getType() const;

		/**
		 * Get the Length of the SOME/IP-SD option
		 * @return size_t
		 */
		size_t getLength() const
		{
			return m_DataLen;
		}

		/**
		 * Get the internal data of the SOME/IP-SD Option
		 * @return uint8_t*
		 */
		uint8_t* getDataPtr() const;

		/**
		 * Get a pointer to the SOME/IP-SD Option base header
		 * @return someipsdhdroptionsbase*
		 */
		someipsdhdroptionsbase* getSomeIpSdOptionHeader() const;

	protected:
		const IDataContainer* m_DataContainer;
		size_t m_Offset;
		uint8_t* m_ShadowData;
		size_t m_DataLen;

		SomeIpSdOption() : m_DataContainer(nullptr), m_Offset(0), m_ShadowData(nullptr), m_DataLen(0)
		{}

		SomeIpSdOption(const IDataContainer* dataContainer, size_t offset)
		    : m_DataContainer(dataContainer), m_Offset(offset), m_ShadowData(nullptr), m_DataLen(0)
		{}

		void initStdFields(OptionType type);

		SomeIpSdOption(const SomeIpSdOption&) = delete;
		SomeIpSdOption& operator=(const SomeIpSdOption&) = delete;
	};

	/**
	 * @class SomeIpSdIPv4Option
	 * Implements the following SOME/IP-SD Options: IPv4 Endpoint, IPv4 Multicast, IPv4 SD Endpoint
	 */
	class SomeIpSdIPv4Option : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/**
		 * Types of options which are implemented with this class
		 */
		enum IPv4OptionType
		{
			/** IPv4 Endpoint Option */
			IPv4Endpoint,
			/** IPv4 Multicast Option */
			IPv4Multicast,
			/** IPv4 SD Endpoint Option */
			IPv4SdEndpoint,
		};

		/**
		 * Construct a new SomeIpSdIPv4 Option object
		 * @param[in] type IPv4 Option type
		 * @param[in] ipAddress Ipv4 address to use
		 * @param[in] port Port to use
		 * @param[in] l4Protocol Protocol to use
		 */
		SomeIpSdIPv4Option(IPv4OptionType type, IPv4Address ipAddress, uint16_t port, SomeIpSdProtocolType l4Protocol);

		/**
		 * Construct a new SomeIpSdIPv4 Option object from already existing memory
		 * @param[in] dataContainer Data containing the SomeIpSdIPv4 Option object
		 * @param[in] offset Offset for dataContainer
		 */
		SomeIpSdIPv4Option(const IDataContainer* dataContainer, size_t offset);

		/**
		 * Get the Ip Address
		 * @return IPv4Address
		 */
		IPv4Address getIpAddress() const;

		/**
		 * Get the Port
		 * @return uint16_t
		 */
		uint16_t getPort() const;

		/**
		 * Get the Protocol
		 * @return SomeIpSdProtocolType
		 */
		SomeIpSdProtocolType getProtocol() const;

	private:
		/**
		 * @struct someipsdhdroptionsipv4
		 * Represents the IPv4 option types for the SOME/IP-SD header
		 */
#pragma pack(push, 1)
		struct someipsdhdroptionsipv4 : someipsdhdroptionsbase
		{
			/* IPv4-Address field */
			uint32_t ipv4Address;
			/* Reserved */
			// cppcheck-suppress duplInheritedMember
			uint8_t reserved;
			/* Layer 4 Protocol field (L4-Proto) - Either UDP or TCP */
			SomeIpSdProtocolType l4Protocol;
			/* Port number of UDP or TCP */
			uint16_t portNumber;
		};
#pragma pack(pop)
	};

	/**
	 * @class SomeIpSdIPv6Option
	 * Implements the following SOME/IP-SD Options: IPv6 Endpoint, IPv6 Multicast, IPv6 SD Endpoint
	 */
	class SomeIpSdIPv6Option : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/**
		 * Types of options which are implemented with this class
		 */
		enum IPv6OptionType
		{
			/** IPv6 Endpoint Option */
			IPv6Endpoint,
			/** IPv6 Multicast Option */
			IPv6Multicast,
			/** IPv6 SD Endpoint Option */
			IPv6SdEndpoint,
		};

		/**
		 * Construct a new SomeIpSdIPv6 Option object
		 * @param[in] type IPv6 Option type
		 * @param[in] ipAddress Ipv6 address to use
		 * @param[in] port Port to use
		 * @param[in] l4Protocol Protocol to use
		 */
		SomeIpSdIPv6Option(IPv6OptionType type, IPv6Address ipAddress, uint16_t port, SomeIpSdProtocolType l4Protocol);

		/**
		 * Construct a new SomeIpSdIPv6 Option object from already existing memory
		 * @param[in] dataContainer Data containing the SomeIpSdIPv6 Option object
		 * @param[in] offset Offset for dataContainer
		 */
		SomeIpSdIPv6Option(const IDataContainer* dataContainer, size_t offset);

		/**
		 * Get the Ip Address
		 * @return IPv6Address
		 */
		IPv6Address getIpAddress() const;

		/**
		 * Get the Port
		 * @return uint16_t
		 */
		uint16_t getPort() const;

		/**
		 * Get the Protocol
		 * @return SomeIpSdProtocolType
		 */
		SomeIpSdProtocolType getProtocol() const;

	private:
		/**
		 * @struct someipsdhdroptionsipv6
		 * Represents the IPv6 option types for the SOME/IP-SD header
		 */
#pragma pack(push, 1)
		struct someipsdhdroptionsipv6 : someipsdhdroptionsbase
		{
			/* IPv6-Address field */
			uint8_t ipv6Address[16];
			/* Reserved */
			// cppcheck-suppress duplInheritedMember
			uint8_t reserved;
			/* Layer 4 Protocol field (L4-Proto) - Either UDP or TCP */
			SomeIpSdProtocolType l4Protocol;
			/* Port number of UDP or TCP */
			uint16_t portNumber;
		};
#pragma pack(pop)
	};

	/**
	 * @class SomeIpSdConfigurationOption
	 * Implements the Configuration option of SOME/IP-SD protocol
	 */
	class SomeIpSdConfigurationOption : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/**
		 * Construct a new Configuration Option object
		 * @param[in] configurationString the configuration string
		 */
		explicit SomeIpSdConfigurationOption(const std::string& configurationString);

		/**
		 * Construct a new Configuration Option object from already existing memory
		 * @param[in] dataContainer Data containing the Configuration Option object
		 * @param[in] offset Offset for dataContainer
		 */
		SomeIpSdConfigurationOption(const IDataContainer* dataContainer, size_t offset);

		/**
		 * Get the configuration string
		 * @return std::string
		 */
		std::string getConfigurationString() const;
	};

	/**
	 * @class SomeIpSdLoadBalancingOption
	 * Implements the Load Balancing option of SOME/IP-SD protocol
	 */
	class SomeIpSdLoadBalancingOption : public SomeIpSdOption
	{
	public:
		friend class SomeIpSdLayer;

		/**
		 * Construct a new Load Balancing object
		 * @param[in] priority Priority of this instance
		 * @param[in] weight Weight of this instance
		 */
		SomeIpSdLoadBalancingOption(uint16_t priority, uint16_t weight);

		/**
		 * Construct a new Option object from already existing memory
		 * @param[in] dataContainer Data containing the option object
		 * @param[in] offset Offset for dataContainer
		 */
		SomeIpSdLoadBalancingOption(const IDataContainer* dataContainer, size_t offset);

		/**
		 * Get the priority fild
		 * @return uint16_t
		 */
		uint16_t getPriority() const;

		/**
		 * Get the weight field
		 * @return uint16_t
		 */
		uint16_t getWeight() const;

	private:
		/**
		 * @struct someipsdhdroptionsload
		 * Represents the Load Balancing option header for SOME/IP-SD
		 */
#pragma pack(push, 1)
		struct someipsdhdroptionsload : someipsdhdroptionsbase
		{
			/* Priority field */
			uint16_t priority;
			/* Weight field */
			uint16_t weight;
		};
#pragma pack(pop)
	};

	/**
	 * @class SomeIpSdEntry
	 * Implementation of the SOME/IP-SD Service Entry and Eventgroup Entry Type
	 */
	class SomeIpSdEntry
	{
	public:
		friend class SomeIpSdLayer;

		/**
		 * Types of entries that can occur in SOME/IP-SD
		 */
		enum class EntryType : uint8_t
		{
			/** Find Service */
			FindService,
			/** Offer Service */
			OfferService,
			/** Stop Offer Service */
			StopOfferService,
			/** Subscribe Eventgroup */
			SubscribeEventgroup,
			/** Stop Subscribe Eventgroup */
			StopSubscribeEventgroup,
			/** Subscribe Eventgroup Acknowledgment */
			SubscribeEventgroupAck,
			/** Subscribe Eventgroup Negative Acknowledgement */
			SubscribeEventgroupNack,
			/** Unknown Entry Type */
			UnknownEntryType
		};

		/**
		 * @struct someipsdhdrentry
		 * Represents the Service Entry Type and Eventgroup Entry Type
		 */
#pragma pack(push, 1)
		struct someipsdhdrentry
		{
			/** Type */
			uint8_t type;
			/** Index 1st option */
			uint8_t indexFirstOption;
			/** Index 2nd option */
			uint8_t indexSecondOption;
#if (BYTE_ORDER == LITTLE_ENDIAN)
			uint8_t
			    /** Numbers of Option #2 (4bit) */
			    nrOpt2 : 4,
			    /** Numbers of Option #1 (4bit) */
			    nrOpt1 : 4;
#else
			uint8_t
			    /** Numbers of Option #1 (4bit) */
			    nrOpt1 : 4,
			    /** Numbers of Option #2 (4bit) */
			    nrOpt2 : 4;
#endif
			/** Service ID */
			uint16_t serviceID;
			/** Instance ID */
			uint16_t instanceID;
			/** Major Version (8 bit) + TTL (24 bit) */
			uint32_t majorVersion_ttl;
			/** Minor Version (Service Entry Type) or Counter + Eventgroup ID (Eventgroup Entry Type) */
			uint32_t data;
		};
#pragma pack(pop)

		/**
		 * Construct a new SOME/IP-SD Service Entry Type
		 * @param[in] type Type to create
		 * @param[in] serviceID ServiceID to use
		 * @param[in] instanceID InstanceID to use
		 * @param[in] majorVersion MajorVersion to use
		 * @param[in] TTL TTL to use. Has to be 0 for all Stop* entry types
		 * @param[in] minorVersion MinorVersion to use
		 */
		SomeIpSdEntry(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion, uint32_t TTL,
		              uint32_t minorVersion);

		/**
		 * Construct a new SOME/IP-SD Eventgroup Entry Type
		 * @param[in] type Type to create
		 * @param[in] serviceID ServiceID to use
		 * @param[in] instanceID InstanceID to use
		 * @param[in] majorVersion MajorVersion to use
		 * @param[in] TTL TTL to use. Has to be 0 for all Stop* entry types
		 * @param[in] counter Counter value to use
		 * @param[in] eventGroupID EventgroupId to use
		 */
		SomeIpSdEntry(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion, uint32_t TTL,
		              uint8_t counter, uint16_t eventGroupID);

		/**
		 * Construct a new SomeIpSdEntry object from existing data
		 * @param[in] pSomeIpSdLayer Layer that this entry is created for
		 * @param[in] offset Offset for pSomeIpSdLayer
		 */
		SomeIpSdEntry(const SomeIpSdLayer* pSomeIpSdLayer, size_t offset);

		/**
		 * Destroy the SomeIpSd Entry object and delete allocated data if it has been allocated by a constructor
		 */
		~SomeIpSdEntry();

		/**
		 * Get the internal data of the SOME/IP-SD Entry
		 * @return uint8_t*
		 */
		uint8_t* getDataPtr() const;

		/**
		 * Get a pointer to the SOME/IP-SD Entry header
		 * @return someipsdhdrentry*
		 */
		someipsdhdrentry* getSomeIpSdEntryHeader() const;

		/**
		 * Get the Entry Type
		 * @return EntryType
		 */
		EntryType getType() const
		{
			return m_EntryType;
		}

		/**
		 * Get the Length of the SomeIpSd Entry
		 * @return size_t
		 */
		size_t getLength() const
		{
			return sizeof(someipsdhdrentry);
		}

		/**
		 * Get the number of Options of this Entry
		 * @return uint32_t
		 */
		uint32_t getNumOptions() const;

		/**
		 * Get the Service Id in host endianness
		 * @return uint16_t
		 */
		uint16_t getServiceId() const;

		/**
		 * Set the Service Id
		 * @param[in] serviceId
		 */
		void setServiceId(uint16_t serviceId);

		/**
		 * Get the Instance Id in host endianness
		 * @return uint16_t
		 */
		uint16_t getInstanceId() const;

		/**
		 * Set the Instance Id
		 * @param[in] instanceId
		 */
		void setInstanceId(uint16_t instanceId);

		/**
		 * Get the Major version field in host endianness
		 * @return uint16_t
		 */
		uint8_t getMajorVersion() const;

		/**
		 * Set the Major Version
		 * @param[in] majorVersion
		 */
		void setMajorVersion(uint8_t majorVersion);

		/**
		 * Get the Ttl field
		 * @return uint32_t
		 */
		uint32_t getTtl() const;

		/**
		 * Set the Ttl field
		 * @param[in] ttl
		 */
		void setTtl(uint32_t ttl);

		/**
		 * Get the minor version
		 * @return uint32_t
		 */
		uint32_t getMinorVersion() const;

		/**
		 * Set the minor version
		 * @param[in] minorVersion
		 */
		void setMinorVersion(uint32_t minorVersion);

		/**
		 * Get the counter value
		 * @return uint32_t
		 */
		uint8_t getCounter() const;

		/**
		 * Set the counter value
		 * @param[in] counter
		 */
		void setCounter(uint8_t counter);

		/**
		 * Get the eventgroup id
		 * @return uint32_t
		 */
		uint16_t getEventgroupId() const;

		/**
		 * Set the eventgroup id
		 * @param[in] eventgroupID
		 */
		void setEventgroupId(uint16_t eventgroupID);

	private:
		/**
		 * These are the entry types used by SOME/IP-SD. They cannot be used for parameter passing since the values
		 * are not unique.
		 */
		enum class TypeInternal : uint8_t
		{
			/** Find Service */
			FindService_Internal = 0x00,
			/** Offer Service / Stop Offer Service */
			OfferService_Internal = 0x01,
			/** Subscribe Eventgroup & Stop Subscribe Eventgroup */
			SubscribeEventgroup_Internal = 0x06,
			/** Subscribe Eventgroup Acknowledgment / Negative Acknowledgement */
			SubscribeEventgroupAck_Internal = 0x07,
		};

		EntryType m_EntryType;
		const SomeIpSdLayer* m_Layer;
		size_t m_Offset;
		uint8_t* m_ShadowData;

		void initStdFields(EntryType type, uint16_t serviceID, uint16_t instanceID, uint8_t majorVersion, uint32_t TTL);

		SomeIpSdEntry(const SomeIpSdEntry&) = delete;
		SomeIpSdEntry& operator=(const SomeIpSdEntry&) = delete;

		static const uint32_t SOMEIPSD_HDR_ENTRY_MASK_TTL = 0x00FFFFFF;
	};

	/**
	 * @class SomeIpSdLayer
	 * Implementation of the SOME/IP-SD protocol
	 */
	class SomeIpSdLayer : public SomeIpLayer
	{
	public:
		friend class SomeIpSdEntry;

		typedef SomeIpSdEntry* EntryPtr;
		typedef std::vector<EntryPtr> EntriesVec;
		typedef SomeIpSdOption* OptionPtr;
		typedef std::vector<OptionPtr> OptionsVec;

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SomeIpSdLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Construct a new SomeIpSdLayer object
		 * @param[in] serviceID Service ID
		 * @param[in] methodID Method ID
		 * @param[in] clientID Client ID
		 * @param[in] sessionID Session ID
		 * @param[in] interfaceVersion Interface Version
		 * @param[in] type Type of the message
		 * @param[in] returnCode Return Code
		 * @param[in] flags Flags that shall be used in the header
		 */
		SomeIpSdLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
		              uint8_t interfaceVersion, MsgType type, uint8_t returnCode, uint8_t flags);

		/**
		 * Destroy the layer object
		 */
		~SomeIpSdLayer()
		{}

		/**
		 * Checks if given port is a SOME/IP-SD protocol port
		 * @param[in] port Port to check
		 * @return true if SOME/IP-SD protocol port, false if not
		 */
		static bool isSomeIpSdPort(uint16_t port)
		{
			return port == 30490;
		}

		/**
		 * The static method makes validation of input data
		 * @param[in] data The pointer to the beginning of byte stream of IP packet
		 * @param[in] dataLen The length of byte stream
		 * @return True if the data is valid and can represent the packet
		 */
		static bool isDataValid(const uint8_t* data, size_t dataLen);

		/**
		 * Get the Flags of the layer
		 * @return uint8_t Flags
		 */
		uint8_t getFlags() const;

		/**
		 * Set the Flags of the layer
		 * @param[in] flags Flags to set
		 */
		void setFlags(uint8_t flags);

		/**
		 * Get the number of entries in this layer
		 * @return uint32_t
		 */
		uint32_t getNumEntries() const;

		/**
		 * Get the number of options in this layer
		 * @return uint32_t
		 */
		uint32_t getNumOptions() const;

		/**
		 * Get the Entries from this layer
		 * @return EntriesVec Vector holding pointers to the options
		 */
		const EntriesVec getEntries() const;

		/**
		 * Get the Options from this layer
		 * @return OptionsVec Vector holding pointers to the options
		 */
		const OptionsVec getOptions() const;

		/**
		 * Get the Options from a specific Entry
		 * @param[in] index Index of the Entry, starting with 0.
		 * @return OptionsVec Vector holding pointers to the options
		 */
		const OptionsVec getOptionsFromEntry(uint32_t index) const;

		/**
		 * Adds a given entry to the layer and returns the index of the entry
		 * @param[in] entry Pointer to the entry that shall be added to the layer
		 * @return uint32_t Returns the index of the entry starting with 0
		 */
		uint32_t addEntry(const SomeIpSdEntry& entry);

		/**
		 * Adds an option to an entry that has already been added to the layer by using addEntry(). The option
		 * is also added to the layer itself. If the option cannot by assigned to the entry, the option is not
		 * copied into the layer.
		 * @param[in] indexEntry Index of the entry where the option shall be added. First Entry has index 0
		 * @param[in] option Pointer to the option that shall be added
		 * @return True if the option could be assigned to the entry and was copied into the layer, false otherwise
		 */
		bool addOptionTo(uint32_t indexEntry, const SomeIpSdOption& option);

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields() {};

		/**
		 * @return The string representation of the SOME/IP-SD layer
		 */
		std::string toString() const;

	private:
		/**
		 * @struct someipsdhdr
		 * Represents an SOME/IP-SD protocol header
		 */
#pragma pack(push, 1)
		struct someipsdhdr : someiphdr
		{
			/** Flags (8 bit) */
			uint8_t flags;
			/** Reserved1 field (Bits 0-7 of 24-bits reserved field) */
			uint8_t reserved1;
			/** Reserved2 field (Bits 8-15 of 24-bits reserved field) */
			uint8_t reserved2;
			/** Reserved3 field (Bits 16-23 of 24-bits reserved field) */
			uint8_t reserved3;
		};
#pragma pack(pop)

		uint32_t m_NumOptions;

		static bool countOptions(uint32_t& count, const uint8_t* data);
		uint32_t findOption(const SomeIpSdOption& option);
		void addOption(const SomeIpSdOption& option);
		bool addOptionIndex(uint32_t indexEntry, uint32_t indexOffset);
		OptionPtr parseOption(SomeIpSdOption::OptionType type, size_t offset) const;

		static size_t getLenEntries(const uint8_t* data);
		size_t getLenEntries() const;
		static size_t getLenOptions(const uint8_t* data);
		size_t getLenOptions() const;
		void setLenEntries(uint32_t length);
		void setLenOptions(uint32_t length);
	};

}  // namespace vanhooks::net
// ---- end SomeIpSdLayer.h ----

