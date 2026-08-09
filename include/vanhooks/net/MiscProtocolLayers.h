#pragma once

// ===== Consolidated header: MiscProtocolLayers.h =====
// Merges: BgpLayer, RadiusLayer, NtpLayer, SSHLayer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "PacketCore.h"
#include "Common.h"

// ---- begin BgpLayer.h ----
#include <vector>

/**
 * @file
 * This file contains classes for parsing, creating and editing Border Gateway Protocol (BGP) version 4 packets.
 * It contains an abstract class named BgpLayer which has common functionality and 5 inherited classes that
 * represent the different BGP message types: OPEN, UPDATE, NOTIFICATION, KEEPALIVE and ROUTE-REFRESH.
 * Each of these classes contains unique functionality for parsing. creating and editing of these message.
 */

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class BgpLayer
	 * Represents Border Gateway Protocol (BGP) v4 protocol layer. This is an abstract class that cannot be
	 * instantiated, and contains functionality which is common to all BGP message types.
	 */
	class BgpLayer : public Layer
	{
	public:
		/**
		 * An enum representing BGP message types
		 */
		enum BgpMessageType
		{
			/** BGP OPEN message */
			Open = 1,
			/** BGP UPDATE message */
			Update = 2,
			/** BGP NOTIFICATION message */
			Notification = 3,
			/** BGP KEEPALIVE message */
			Keepalive = 4,
			/** BGP ROUTE-REFRESH message */
			RouteRefresh = 5,
		};

#pragma pack(push, 1)
		/**
		 * @struct bgp_common_header
		 * Represents the common fields of a BGP 4 message
		 */
		struct bgp_common_header
		{
			/** 16-octet marker */
			uint8_t marker[16];
			/** Total length of the message, including the header */
			uint16_t length;
			/** BGP message type */
			uint8_t messageType;
		};
#pragma pack(pop)

		/**
		 * @return BGP message type
		 */
		virtual BgpMessageType getBgpMessageType() const = 0;

		/**
		 * @return BGP message type as string. Return value can be one of the following:
		 * "OPEN", "UPDATE", "NOTIFICATION", "KEEPALIVE", "ROUTE-REFRESH", "Unknown"
		 */
		std::string getMessageTypeAsString() const;

		/**
		 * A static method that checks whether a source or dest port match those associated with the BGP protocol
		 * @param[in] portSrc Source port number to check
		 * @param[in] portDst Dest port number to check
		 * @return True if the source or dest port match those associated with the BGP protocol
		 */
		static bool isBgpPort(uint16_t portSrc, uint16_t portDst)
		{
			return portSrc == 179 || portDst == 179;
		}

		/**
		 * A method that creates a BGP layer from packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored
		 * @return A newly allocated BGP layer of one of the following types (according to the message type):
		 * BgpOpenMessageLayer, BgpUpdateMessageLayer, BgpNotificationMessageLayer, BgpKeepaliveMessageLayer,
		 * BgpRouteRefreshMessageLayer
		 */
		static BgpLayer* parseBgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/**
		 * @return The size of the BGP message
		 */
		size_t getHeaderLen() const;

		/**
		 * Multiple BGP messages can reside in a single packet, and the only layer that can come after a BGP message
		 * is another BGP message. This method checks for remaining data and parses it as another BGP layer
		 */
		void parseNextLayer();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

		/**
		 * Calculates the basic BGP fields:
		 * - Set marker to all ones
		 * - Set message type value
		 * - Set message length
		 */
		void computeCalculateFields();

	protected:
		// protected c'tors, this class cannot be instantiated by users
		BgpLayer()
		{}
		BgpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, BGP)
		{}

		bgp_common_header* getBasicHeader() const
		{
			return (bgp_common_header*)m_Data;
		}

		void setBgpFields(size_t messageLen = 0);
	};

	/**
	 * @class BgpOpenMessageLayer
	 * Represents a BGP v4 OPEN message
	 */
	class BgpOpenMessageLayer : public BgpLayer
	{
	public:
#pragma pack(push, 1)
		/**
		 * @struct bgp_open_message
		 * BGP OPEN message structure
		 */
		typedef struct bgp_open_message : bgp_common_header
		{
			/** BGP version number */
			uint8_t version;
			/** Autonomous System number of the sender */
			uint16_t myAutonomousSystem;
			/** The number of seconds the sender proposes for the value of the Hold Timer */
			uint16_t holdTime;
			/** BGP Identifier of the sender */
			uint32_t bgpId;
			/** The total length of the Optional Parameters field */
			uint8_t optionalParameterLength;
		} bgp_open_message;
#pragma pack(pop)

		/**
		 * @struct optional_parameter
		 * A structure that represents BGP OPEN message optional parameters
		 */
		struct optional_parameter
		{
			/** Parameter type */
			uint8_t type;
			/** Parameter length */
			uint8_t length;
			/** Parameter data */
			uint8_t value[32];

			/**
			 * A default c'tor that zeroes all data
			 */
			optional_parameter()
			{}

			/**
			 * A c'tor that initializes the values of the struct
			 * @param[in] typeVal Parameter type value
			 * @param[in] valueAsHexString Parameter data as hex string. The length field will be set accordingly.
			 * If this parameter is not a valid hex string the data will remain zeroed and length will be also zero
			 */
			optional_parameter(uint8_t typeVal, const std::string& valueAsHexString);
		};

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		BgpOpenMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A c'tor that creates a new BGP OPEN message
		 * @param[in] myAutonomousSystem The Autonomous System number of the sender
		 * @param[in] holdTime The number of seconds the sender proposes for the value of the Hold Timer
		 * @param[in] bgpId The BGP Identifier of the sender
		 * @param[in] optionalParams A vector of optional parameters. This parameter is optional and if not provided no
		 * parameters will be set on the message
		 */
		BgpOpenMessageLayer(uint16_t myAutonomousSystem, uint16_t holdTime, const IPv4Address& bgpId,
		                    const std::vector<optional_parameter>& optionalParams = std::vector<optional_parameter>());

		/**
		 * Get a pointer to the open message data. Notice this points directly to the data, so any change will modify
		 * the actual packet data
		 * @return A pointer to a bgp_open_message structure containing the data
		 */
		bgp_open_message* getOpenMsgHeader() const
		{
			return (bgp_open_message*)m_Data;
		}

		/**
		 * @return The BGP identifier as IPv4Address object
		 */
		IPv4Address getBgpId() const
		{
			return IPv4Address(getOpenMsgHeader()->bgpId);
		}

		/**
		 * Set the BGP identifier
		 * @param[in] newBgpId BGP identifier to set. If value is not a valid IPv4 address it won't be set
		 */
		void setBgpId(const IPv4Address& newBgpId);

		/**
		 * Get a vector of the optional parameters in the message
		 * @param[out] optionalParameters The vector where the optional parameters will be written to. This method
		 * doesn't remove any existing data on this vector before pushing data to it
		 */
		void getOptionalParameters(std::vector<optional_parameter>& optionalParameters);

		/**
		 * @return The length in [bytes] of the optional parameters data in the message
		 */
		size_t getOptionalParametersLength();

		/**
		 * Set optional parameters in the message. This method will override all existing optional parameters currently
		 * in the message. If the input is an empty vector all optional parameters will be cleared. This method
		 * automatically sets the bgp_common_header#length and the bgp_open_message#optionalParameterLength fields on
		 * the message
		 * @param[in] optionalParameters A vector of new optional parameters to set in the message
		 * @return True if all optional parameters were set successfully or false otherwise. In case of an error an
		 * appropriate message will be printed to log
		 */
		bool setOptionalParameters(const std::vector<optional_parameter>& optionalParameters);

		/**
		 * Clear all optional parameters currently in the message. This is equivalent to calling setOptionalParameters()
		 * with an empty vector as a parameter
		 * @return True if all optional parameters were successfully cleared or false otherwise. In case of an error an
		 * appropriate message will be printed to log
		 */
		bool clearOptionalParameters();

		// implement abstract methods

		BgpMessageType getBgpMessageType() const
		{
			return BgpLayer::Open;
		}

	private:
		size_t optionalParamsToByteArray(const std::vector<optional_parameter>& optionalParams, uint8_t* resultByteArr,
		                                 size_t maxByteArrSize);
	};

	/**
	 * @class BgpUpdateMessageLayer
	 * Represents a BGP v4 UPDATE message
	 */
	class BgpUpdateMessageLayer : public BgpLayer
	{
	public:
		/**
		 * @struct prefix_and_ip
		 * A structure that contains IPv4 address and IP address mask (prefix) information.
		 * It's used to represent BGP Withdrawn Routes and Network Layer Reachability Information (NLRI)
		 */
		struct prefix_and_ip
		{
			/** IPv4 address mask, must contain one of the values: 8, 16, 24, 32 */
			uint8_t prefix;
			/** IPv4 address */
			IPv4Address ipAddr;

			/**
			 * A default c'tor that zeroes all data
			 */
			prefix_and_ip() : prefix(0), ipAddr(IPv4Address::Zero)
			{}

			/**
			 * A c'tor that initializes the values of the struct
			 * @param[in] prefixVal IPv4 address mask value
			 * @param[in] ipAddrVal IPv4 address
			 */
			prefix_and_ip(uint8_t prefixVal, const std::string& ipAddrVal) : prefix(prefixVal), ipAddr(ipAddrVal)
			{}
		};

		/**
		 * @struct path_attribute
		 * A structure that represents BGP OPEN message Path Attributes information
		 */
		struct path_attribute
		{
			/** Path attribute flags */
			uint8_t flags;
			/** Path attribute type */
			uint8_t type;
			/** Path attribute length */
			uint8_t length;
			/** Path attribute data. Max supported data length is 32 bytes */
			uint8_t data[32];

			/**
			 * A default c'tor that zeroes all data
			 */
			path_attribute()
			{}

			/**
			 * A c'tor that initializes the values of the struct
			 * @param[in] flagsVal Path attribute flags value
			 * @param[in] typeVal Path attribute type value
			 * @param[in] dataAsHexString Path attribute data as hex string. The path_attribute#length field will be set
			 * accordingly. If this parameter is not a valid hex string the data will remain zeroed and length will be
			 * also set to zero
			 */
			path_attribute(uint8_t flagsVal, uint8_t typeVal, const std::string& dataAsHexString);
		};

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		BgpUpdateMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A static method that takes a byte array and detects whether it is a BgpUpdateMessage
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data looks like a valid BgpUpdateMessage layer
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		/**
		 * A c'tor that creates a new BGP UPDATE message
		 * @param[in] withdrawnRoutes A vector of withdrawn routes data. If left empty (which is the default value) no
		 * withdrawn route information will be written to the message
		 * @param[in] pathAttributes A vector of path attributes data. If left empty (which is the default value) no
		 * path attribute information will be written to the message
		 * @param[in] nlri A vector of network layer reachability data. If left empty (which is the default value) no
		 * reachability information will be written to the message
		 */
		explicit BgpUpdateMessageLayer(
		    const std::vector<prefix_and_ip>& withdrawnRoutes = std::vector<prefix_and_ip>(),
		    const std::vector<path_attribute>& pathAttributes = std::vector<path_attribute>(),
		    const std::vector<prefix_and_ip>& nlri = std::vector<prefix_and_ip>());

		/**
		 * Get a pointer to the basic BGP message data. Notice this points directly to the data, so any change will
		 * modify the actual packet data
		 * @return A pointer to a bgp_common_header structure containing the data
		 */
		bgp_common_header* getBasicMsgHeader() const
		{
			return (bgp_common_header*)m_Data;
		}

		/**
		 * @return The size in [bytes] of the Withdrawn Routes data
		 */
		size_t getWithdrawnRoutesLength() const;

		/**
		 * Get a vector of the Withdrawn Routes currently in the message
		 * @param[out] withdrawnRoutes A reference to a vector the Withdrawn Routes data will be written to
		 */
		void getWithdrawnRoutes(std::vector<prefix_and_ip>& withdrawnRoutes);

		/**
		 * Set Withdrawn Routes in this message. This method will override any existing Withdrawn Routes in the message.
		 * If the input is an empty vector all Withdrawn Routes will be removed. This method automatically sets the
		 * bgp_common_header#length and the Withdrawn Routes length fields in the message
		 * @param[in] withdrawnRoutes New Withdrawn Routes to set in the message
		 * @return True if all Withdrawn Routes were set successfully or false otherwise. In case of an error an
		 * appropriate message will be printed to log
		 */
		bool setWithdrawnRoutes(const std::vector<prefix_and_ip>& withdrawnRoutes);

		/**
		 * Clear all Withdrawn Routes data currently in the message. This is equivalent to calling setWithdrawnRoutes()
		 * with an empty vector as a parameter
		 * @return True if all Withdrawn Routes were successfully cleared or false otherwise. In case of an error an
		 * appropriate message will be printed to log
		 */
		bool clearWithdrawnRoutes();

		/**
		 * @return The size in [bytes] of the Path Attributes data
		 */
		size_t getPathAttributesLength() const;

		/**
		 * Get a vector of the Path Attributes currently in the message
		 * @param[out] pathAttributes A reference to a vector the Path Attributes data will be written to
		 */
		void getPathAttributes(std::vector<path_attribute>& pathAttributes);

		/**
		 * Set Path Attributes in this message. This method will override any existing Path Attributes in the message.
		 * If the input is an empty vector all Path Attributes will be removed. This method automatically sets the
		 * bgp_common_header#length and the Path Attributes length fields in the message
		 * @param[in] pathAttributes New Path Attributes to set in the message
		 * @return True if all Path Attributes were set successfully or false otherwise. In case of an error an
		 * appropriate message will be printed to log
		 */
		bool setPathAttributes(const std::vector<path_attribute>& pathAttributes);

		/**
		 * Clear all Path Attributes data currently in the message. This is equivalent to calling setPathAttributes()
		 * with an empty vector as a parameter
		 * @return True if all Path Attributes were successfully cleared or false otherwise. In case of an error an
		 * appropriate message will be printed to log
		 */
		bool clearPathAttributes();

		/**
		 * @return The size in [bytes] of the Network Layer Reachability Info
		 */
		size_t getNetworkLayerReachabilityInfoLength() const;

		/**
		 * Get a vector of the Network Layer Reachability Info currently in the message
		 * @param[out] nlri A reference to a vector the NLRI data will be written to
		 */
		void getNetworkLayerReachabilityInfo(std::vector<prefix_and_ip>& nlri);

		/**
		 * Set NLRI data in this message. This method will override any existing NLRI data in the message.
		 * If the input is an empty vector all NLRI data will be removed. This method automatically sets the
		 * bgp_common_header#length field in the message
		 * @param[in] nlri New NLRI data to set in the message
		 * @return True if all NLRI data was set successfully or false otherwise. In case of an error an appropriate
		 * message will be printed to log
		 */
		bool setNetworkLayerReachabilityInfo(const std::vector<prefix_and_ip>& nlri);

		/**
		 * Clear all NLRI data currently in the message. This is equivalent to calling setNetworkLayerReachabilityInfo()
		 * with an empty vector as a parameter
		 * @return True if all NLRI were successfully cleared or false otherwise. In case of an error an appropriate
		 * message will be printed to log
		 */
		bool clearNetworkLayerReachabilityInfo();

		// implement abstract methods

		BgpMessageType getBgpMessageType() const
		{
			return BgpLayer::Update;
		}

	private:
		void parsePrefixAndIPData(uint8_t* dataPtr, size_t dataLen, std::vector<prefix_and_ip>& result);

		size_t prefixAndIPDataToByteArray(const std::vector<prefix_and_ip>& prefixAndIpData, uint8_t* resultByteArr,
		                                  size_t maxByteArrSize);

		size_t pathAttributesToByteArray(const std::vector<path_attribute>& pathAttributes, uint8_t* resultByteArr,
		                                 size_t maxByteArrSize);
	};

	/**
	 * @class BgpNotificationMessageLayer
	 * Represents a BGP v4 NOTIFICATION message
	 */
	class BgpNotificationMessageLayer : public BgpLayer
	{
	public:
#pragma pack(push, 1)
		/**
		 * @struct bgp_notification_message
		 * BGP NOTIFICATION message structure
		 */
		typedef struct bgp_notification_message : bgp_common_header
		{
			/** BGP notification error code */
			uint8_t errorCode;
			/** BGP notification error sub-code */
			uint8_t errorSubCode;
		} bgp_notification_message;
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		BgpNotificationMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A c'tor that creates a new BGP NOTIFICATION message
		 * @param[in] errorCode BGP notification error code
		 * @param[in] errorSubCode BGP notification error sub code
		 */
		BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode);

		/**
		 * A c'tor that creates a new BGP Notification message
		 * @param[in] errorCode BGP notification error code
		 * @param[in] errorSubCode BGP notification error sub code
		 * @param[in] notificationData A byte array that contains the notification data
		 * @param[in] notificationDataLen The size of the byte array that contains the notification data
		 */
		BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData,
		                            size_t notificationDataLen);

		/**
		 * A c'tor that creates a new BGP Notification message
		 * @param[in] errorCode BGP notification error code
		 * @param[in] errorSubCode BGP notification error sub code
		 * @param[in] notificationData A hex string that contains the notification data. This string will be converted
		 * to a byte array that will be added to the message. If the input isn't a valid hex string notification data
		 * will remain empty and an error will be printed to log
		 */
		BgpNotificationMessageLayer(uint8_t errorCode, uint8_t errorSubCode, const std::string& notificationData);

		/**
		 * Get a pointer to the notification message data. Notice this points directly to the data, so any change will
		 * modify the actual packet data
		 * @return A pointer to a bgp_notification_message structure containing the data
		 */
		bgp_notification_message* getNotificationMsgHeader() const
		{
			return (bgp_notification_message*)m_Data;
		}

		/**
		 * @return The size in [bytes] of the notification data. Notification data is a variable-length field used to
		 * diagnose the reason for the BGP NOTIFICATION
		 */
		size_t getNotificationDataLen() const;

		/**
		 * @return A pointer to the notification data. Notification data is a variable-length field used to diagnose the
		 * reason for the BGP NOTIFICATION
		 */
		uint8_t* getNotificationData() const;

		/**
		 * @return A hex string which represents the notification data. Notification data is a variable-length field
		 * used to diagnose the reason for the BGP NOTIFICATION
		 */
		std::string getNotificationDataAsHexString() const;

		/**
		 * Set the notification data. This method will extend or shorten the existing layer to include the new
		 * notification data. If newNotificationData is nullptr or newNotificationDataLen is zero then notification data
		 * will be set to none.
		 * @param[in] newNotificationData A byte array containing the new notification data
		 * @param[in] newNotificationDataLen The size of the byte array
		 * @return True if notification data was set successfully or false if any error occurred. In case of an error an
		 * appropriate error message will be printed to log
		 */
		bool setNotificationData(const uint8_t* newNotificationData, size_t newNotificationDataLen);

		/**
		 * Set the notification data. This method will extend or shorten the existing layer to include the new
		 * notification data. If newNotificationDataAsHexString is an empty string then notification data will be set to
		 * none.
		 * @param[in] newNotificationDataAsHexString A hex string representing the new notification data. If the string
		 * is not a valid hex string no data will be changed and an error will be returned
		 * @return True if notification data was set successfully or false if any error occurred or if the string is not
		 * a valid hex string. In case of an error an appropriate error message will be printed to log
		 */
		bool setNotificationData(const std::string& newNotificationDataAsHexString);

		// implement abstract methods

		BgpMessageType getBgpMessageType() const
		{
			return BgpLayer::Notification;
		}

	private:
		void initMessageData(uint8_t errorCode, uint8_t errorSubCode, const uint8_t* notificationData,
		                     size_t notificationDataLen);
	};

	/**
	 * @class BgpKeepaliveMessageLayer
	 * Represents a BGP v4 KEEPALIVE message
	 */
	class BgpKeepaliveMessageLayer : public BgpLayer
	{
	public:
		/**
		 * @typedef bgp_keepalive_message
		 * BGP KEEPALIVE message structure
		 */
		typedef bgp_common_header bgp_keepalive_message;

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		BgpKeepaliveMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A c'tor that creates a new BGP KEEPALIVE message
		 */
		BgpKeepaliveMessageLayer();

		/**
		 * Get a pointer to the KeepAlive message data. Notice this points directly to the data, so any change will
		 * modify the actual packet data
		 * @return A pointer to a bgp_keepalive_message structure containing the data
		 */
		bgp_keepalive_message* getKeepaliveHeader() const
		{
			return (bgp_keepalive_message*)getBasicHeader();
		}

		// implement abstract methods

		BgpMessageType getBgpMessageType() const
		{
			return BgpLayer::Keepalive;
		}
	};

	/**
	 * @class BgpRouteRefreshMessageLayer
	 * Represents a BGP v4 ROUTE-REFRESH message
	 */
	class BgpRouteRefreshMessageLayer : public BgpLayer
	{
	public:
#pragma pack(push, 1)
		/**
		 * @struct bgp_route_refresh_message
		 * BGP ROUTE-REFRESH message structure
		 */
		typedef struct bgp_route_refresh_message : bgp_common_header
		{
			/** Address Family Identifier */
			uint16_t afi;
			/** Reserved field */
			uint8_t reserved;
			/** Subsequent Address Family Identifier */
			uint8_t safi;
		} bgp_route_refresh_message;
#pragma pack(pop)

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		BgpRouteRefreshMessageLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : BgpLayer(data, dataLen, prevLayer, packet)
		{}

		/**
		 * A c'tor that creates a new BGP ROUTE-REFRESH message
		 * @param[in] afi The Address Family Identifier (AFI) value to set in the message
		 * @param[in] safi The Subsequent Address Family Identifier (SAFI) value to set in the message
		 */
		BgpRouteRefreshMessageLayer(uint16_t afi, uint8_t safi);

		/**
		 * Get a pointer to the ROUTE-REFRESH message data. Notice this points directly to the data, so any change will
		 * modify the actual packet data
		 * @return A pointer to a bgp_route_refresh_message structure containing the data
		 */
		bgp_route_refresh_message* getRouteRefreshHeader() const
		{
			return (bgp_route_refresh_message*)getBasicHeader();
		}

		// implement abstract methods

		BgpMessageType getBgpMessageType() const
		{
			return BgpLayer::RouteRefresh;
		}
	};

}  // namespace vanhooks::net
// ---- end BgpLayer.h ----

// ---- begin RadiusLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct radius_header
	 * Represents a RADIUS protocol header
	 */
#pragma pack(push, 1)
	struct radius_header
	{
		/** RADIUS message code */
		uint8_t code;
		/** RADIUS message ID */
		uint8_t id;
		/** RADIUS message length */
		uint16_t length;
		/** Used to authenticate the reply from the RADIUS server and to encrypt passwords */
		uint8_t authenticator[16];
	};
#pragma pack(pop)

	/**
	 * @class RadiusAttribute
	 * A wrapper class for RADIUS attributes. This class does not create or modify RADIUS attribute records, but rather
	 * serves as a wrapper and provides useful methods for retrieving data from them
	 */
	class RadiusAttribute : public TLVRecord<uint8_t, uint8_t>
	{
	public:
		/**
		 * A c'tor for this class that gets a pointer to the attribute raw data (byte array)
		 * @param[in] attrRawData A pointer to the attribute raw data
		 */
		explicit RadiusAttribute(uint8_t* attrRawData) : TLVRecord(attrRawData)
		{}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		virtual ~RadiusAttribute()
		{}

		// implement abstract methods

		size_t getTotalSize() const
		{
			if (m_Data == nullptr)
				return 0;

			return (size_t)m_Data->recordLen;
		}

		size_t getDataSize() const
		{
			if (m_Data == nullptr)
				return 0;

			return (size_t)m_Data->recordLen - 2 * sizeof(uint8_t);
		}
	};

	/**
	 * @class RadiusAttributeBuilder
	 * A class for building RADIUS attributes. This builder receives the attribute parameters in its c'tor,
	 * builds the RADIUS attribute raw buffer and provides a build() method to get a RadiusAttribute object out of it
	 */
	class RadiusAttributeBuilder : public TLVRecordBuilder
	{
	public:
		/**
		 * A c'tor for building RADIUS attributes which their value is a byte array. The RadiusAttribute object can
		 * later be retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A buffer containing the attribute value. This buffer is read-only and isn't modified in
		 * any way
		 * @param[in] attrValueLen Attribute value length in bytes
		 */
		RadiusAttributeBuilder(uint8_t attrType, const uint8_t* attrValue, uint8_t attrValueLen)
		    : TLVRecordBuilder(attrType, attrValue, attrValueLen)
		{}

		/**
		 * A c'tor for building RADIUS attributes which have a 1-byte value. The RadiusAttribute object can later be
		 * retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A 1-byte attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, uint8_t attrValue) : TLVRecordBuilder(attrType, attrValue)
		{}

		/**
		 * A c'tor for building RADIUS attributes which have a 2-byte value. The RadiusAttribute object can later be
		 * retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A 2-byte attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, uint16_t attrValue) : TLVRecordBuilder(attrType, attrValue)
		{}

		/**
		 * A c'tor for building RADIUS attributes which have a 4-byte value. The RadiusAttribute object can later be
		 * retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue A 4-byte attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, uint32_t attrValue) : TLVRecordBuilder(attrType, attrValue)
		{}

		/**
		 * A c'tor for building RADIUS attributes which have an IPv4Address value. The RadiusAttribute object can later
		 * be retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue The IPv4 address attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, const IPv4Address& attrValue) : TLVRecordBuilder(attrType, attrValue)
		{}

		/**
		 * A c'tor for building RADIUS attributes which have a string value. The RadiusAttribute object can later be
		 * retrieved by calling build()
		 * @param[in] attrType RADIUS attribute type
		 * @param[in] attrValue The string attribute value
		 */
		RadiusAttributeBuilder(uint8_t attrType, const std::string& attrValue) : TLVRecordBuilder(attrType, attrValue)
		{}

		/**
		 * A copy c'tor which copies all the data from another instance of RadiusAttributeBuilder
		 * @param[in] other The instance to copy from
		 */
		RadiusAttributeBuilder(const RadiusAttributeBuilder& other) : TLVRecordBuilder(other)
		{}

		/**
		 * Assignment operator that copies all data from another instance of RadiusAttributeBuilder
		 * @param[in] other The instance to assign from
		 */
		RadiusAttributeBuilder& operator=(const RadiusAttributeBuilder& other)
		{
			TLVRecordBuilder::operator=(other);
			return *this;
		}

		/**
		 * Build the RadiusAttribute object out of the parameters defined in the c'tor
		 * @return The RadiusAttribute object
		 */
		RadiusAttribute build() const;
	};

	/**
	 * @class RadiusLayer
	 * Represents a RADIUS (Remote Authentication Dial-In User Service) protocol layer
	 */
	class RadiusLayer : public Layer
	{
	private:
		TLVRecordReader<RadiusAttribute> m_AttributeReader;

		uint8_t* getAttributesBasePtr() const
		{
			return m_Data + sizeof(radius_header);
		}

		RadiusAttribute addAttrAt(const RadiusAttributeBuilder& attrBuilder, int offset);

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		RadiusLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Radius)
		{}

		/**
		 * A constructor that creates a new layer from scratch
		 * @param[in] code The RADIUS message code
		 * @param[in] id The RADIUS message ID
		 * @param[in] authenticator A pointer to a byte array containing the authenticator value
		 * @param[in] authenticatorArrSize The authenticator byte array size. A valid size of the authenticator field is
		 * 16 bytes. If the provided size is less than that then the byte array will be copied to the packet but the
		 * missing bytes will stay zero. If the size is more than 16 bytes, only the first 16 bytes will be copied to
		 * the packet
		 */
		RadiusLayer(uint8_t code, uint8_t id, const uint8_t* authenticator, uint8_t authenticatorArrSize);

		/**
		 * A constructor that creates a new layer from scratch
		 * @param[in] code The RADIUS message code
		 * @param[in] id The RADIUS message ID
		 * @param[in] authenticator A hex string representing the authenticator value. A valid size of the authenticator
		 * field is 16 bytes. If the hex string represents an array that is smaller than this then the missing bytes in
		 * the packet's authenticator field will stay zero. If the hex string represents an array that is larger than 16
		 * bytes, only the first 16 bytes will be copied to the packet
		 */
		RadiusLayer(uint8_t code, uint8_t id, const std::string& authenticator);

		/**
		 * A d'tor for this layer, currently does nothing
		 */
		~RadiusLayer()
		{}

		/**
		 * Get a pointer to the RADIUS header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the radius_header object
		 */
		radius_header* getRadiusHeader() const
		{
			return (radius_header*)m_Data;
		}

		/**
		 * @return A hex string representation of the radius_header#authenticator byte array value
		 */
		std::string getAuthenticatorValue() const;

		/**
		 * Setter for radius_header#authenticator
		 * @param[in] authValue A hex string representing the requested authenticator value
		 */
		void setAuthenticatorValue(const std::string& authValue);

		/**
		 * A static method that returns the RADIUS message string for a give message code. For example: the string
		 * "Access-Request" will be returned for code 1
		 * @param[in] radiusMessageCode RADIUS message code
		 * @return RADIUS message string
		 */
		static std::string getRadiusMessageString(uint8_t radiusMessageCode);

		/**
		 * @return The first RADIUS attribute in the packet. If there are no attributes the returned value will contain
		 * a logical null (RadiusAttribute#isNull() == true)
		 */
		RadiusAttribute getFirstAttribute() const;

		/**
		 * Get the RADIUS attribute that comes after a given attribute. If the given attribute was the last one, the
		 * returned value will contain a logical null (RadiusAttribute#isNull() == true)
		 * @param[in] attr A given attribute
		 * @return A RadiusAttribute object containing the attribute data that comes next, or logical null if the
		 * given attribute: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		 */
		RadiusAttribute getNextAttribute(RadiusAttribute& attr) const;

		/**
		 * Get a RADIUS attribute by attribute type
		 * @param[in] attrType RADIUS attribute type
		 * @return A RadiusAttribute object containing the first attribute data that matches this type, or logical
		 * null (RadiusAttribute#isNull() == true) if no such attribute found
		 */
		RadiusAttribute getAttribute(uint8_t attrType) const;

		/**
		 * @return The number of RADIUS attributes in the packet
		 */
		size_t getAttributeCount() const;

		/**
		 * Add a new RADIUS attribute at the end of the layer
		 * @param[in] attrBuilder A RadiusAttributeBuilder object that contains the requested attribute data to add
		 * @return A RadiusAttribute object containing the newly added RADIUS attribute data or logical null
		 * (RadiusAttribute#isNull() == true) if addition failed
		 */
		RadiusAttribute addAttribute(const RadiusAttributeBuilder& attrBuilder);

		/**
		 * Add a new RADIUS attribute after an existing one
		 * @param[in] attrBuilder A RadiusAttributeBuilder object that contains the requested attribute data to add
		 * @param[in] prevAttrType The RADIUS attribute which the newly added attribute will come after
		 * @return A RadiusAttribute object containing the newly added RADIUS attribute data or logical null
		 * (RadiusAttribute#isNull() == true) if addition failed
		 */
		RadiusAttribute addAttributeAfter(const RadiusAttributeBuilder& attrBuilder, uint8_t prevAttrType);

		/**
		 * Remove an existing RADIUS attribute from the layer
		 * @param[in] attrType The RADIUS attribute type to remove
		 * @return True if the RADIUS attribute was successfully removed or false if type wasn't found or if removal
		 * failed
		 */
		bool removeAttribute(uint8_t attrType);

		/**
		 * Remove all RADIUS attributes in this layer
		 * @return True if all attributes were successfully removed or false if removal failed for some reason
		 */
		bool removeAllAttributes();

		/**
		 * The static method makes validation of UDP data
		 * @param[in] udpData The pointer to the UDP payload data. It points to the first byte of RADIUS header.
		 * @param[in] udpDataLen The payload data size
		 * @return True if the data is valid and can represent the RADIUS packet
		 */
		static bool isDataValid(const uint8_t* udpData, size_t udpDataLen);

		/**
		 * A static method that checks whether the port is considered as RADIUS
		 * @param[in] port The port number to be checked
		 */
		static inline bool isRadiusPort(uint16_t port);

		// implement abstract methods

		/**
		 * @return The size written in radius_header#length
		 */
		size_t getHeaderLen() const;

		/**
		 * Does nothing for this layer, RADIUS is always last
		 */
		void parseNextLayer()
		{}

		/**
		 * Calculate and store the value of radius_header#length according to the layer size
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}
	};

	// implementation of inline methods

	bool RadiusLayer::isRadiusPort(uint16_t port)
	{
		switch (port)
		{
		case 1812:
		case 1813:
		case 3799:
			return true;
		default:
			return false;
		}
	}  // isRadiusPort

}  // namespace vanhooks::net
// ---- end RadiusLayer.h ----

// ---- begin NtpLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @class NtpLayer
	 * Represents a NTP (Network Time Protocol) layer
	 *
	 * @brief The NTP packet consists of an integral number of 32-bit (4 octet) words in network byte order.
	 * The packet format consists of three components: the header itself, one or more optional extension fields (for
	 * v4), and an optional message authentication code (MAC). Currently the extension fields are not supported. The NTP
	 * header is:
	 *
	 * @verbatim
	   0                   1                   2                   3
	   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                         Root Delay                            |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                         Root Dispersion                       |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                          Reference ID                         |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  +                     Reference Timestamp (64)                  +
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  +                      Origin Timestamp (64)                    +
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  +                      Receive Timestamp (64)                   +
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  +                      Transmit Timestamp (64)                  +
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  .                                                               .
	  .                Extension Field 1 (variable, only v4)          .
	  .                                                               .
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  .                                                               .
	  .                Extension Field 1 (variable, only v4)          .
	  .                                                               .
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                          Key Identifier                       |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	  |                                                               |
	  |                   dgst (128 for v4, 64 for v3)                |
	  |                                                               |
	  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 @endverbatim
	 *
	 */
	class NtpLayer : public Layer
	{
	private:
#pragma pack(push, 1)
		struct ntp_header
		{
#if (BYTE_ORDER == LITTLE_ENDIAN)
			/// 3-bit integer representing the mode
			uint8_t mode : 3,
			    /// 3-bit integer representing the NTP version number
			    version : 3,
			    /// LI Leap Indicator (leap): 2-bit integer warning of an impending leap second to be inserted or
			    /// deleted in the last minute of the current month
			    leapIndicator : 2;
#else
			/// LI Leap Indicator (leap): 2-bit integer warning of an impending leap second to be inserted or deleted in
			/// the last minute of the current month
			uint8_t leapIndicator : 2,
			    /// 3-bit integer representing the NTP version number
			    version : 3,
			    /// 3-bit integer representing the mode
			    mode : 3;
#endif
			/// 8-bit integer representing the stratum
			uint8_t stratum;
			/// Total round-trip delay to the reference clock, in log2 seconds.
			int8_t pollInterval,
			    /// 8-bit signed integer representing the precision of the system clock, in log2 seconds.
			    precision;
			/// Total round-trip delay to the reference clock, in NTP short format.
			uint32_t rootDelay,
			    /// Total dispersion to the reference clock, in NTP short format.
			    rootDispersion,
			    /// 32-bit code identifying the particular server or reference clock.  The interpretation depends on the
			    /// value in the stratum field.
			    referenceIdentifier;
			/// Time when the system clock was last set or corrected, in NTP timestamp format.
			uint64_t referenceTimestamp,
			    /// Time at the client when the request departed for the server, in NTP timestamp format.
			    originTimestamp,
			    /// Time at the client when the request departed for the server, in NTP timestamp format.
			    receiveTimestamp,
			    /// Time at the server when the response left for the client, in NTP timestamp format.
			    transmitTimestamp;
		};
#pragma pack(pop)

#pragma pack(push, 1)
		struct ntp_v3_auth
		{
			/// An integer identifying the cryptographic key used to generate the message-authentication code
			uint32_t keyID;
			/// This is an integer identifying the cryptographic key used to generate the message-authentication code.
			uint8_t dgst[8];  // 64 bit DES based
		};
#pragma pack(pop)

#pragma pack(push, 1)
		struct ntp_v4_auth_md5
		{
			/// 32-bit unsigned integer used by the client and server to designate a secret 128-bit MD5 key.
			uint32_t keyID;
			/// 128-bit MD5 hash
			uint8_t dgst[16];
		};
#pragma pack(pop)

#pragma pack(push, 1)
		struct ntp_v4_auth_sha1
		{
			/// 32-bit unsigned integer used by the client and server to designate a secret 160-bit SHA1 key.
			uint32_t keyID;
			/// 160-bit SHA1 hash
			uint8_t dgst[20];
		};
#pragma pack(pop)

		ntp_header* getNtpHeader() const
		{
			return (ntp_header*)m_Data;
		}

	public:
		/**
		 * Warning of an impending leap second to be inserted or deleted in the last minute of the current month
		 */
		enum LeapIndicator
		{
			/// Normal, no leap second
			NoWarning = 0,
			/// Last minute of the day has 61 seconds
			Last61Secs,
			/// Last minute of the day has 59 seconds
			Last59Secs,
			/// Unknown (clock unsynchronized)
			Unknown
		};

		/**
		 * Representing the NTP association modes
		 */
		enum Mode
		{
			/// Reserved variable
			Reserved = 0,
			/// Symmetrically active
			SymActive,
			/// Symmetrically passive
			SymPassive,
			/// Client mode
			Client,
			/// Server mode
			Server,
			/// Broadcasting mode
			Broadcast,
			/// NTP control messages
			Control,
			/// Reserved for private use
			PrivateUse
		};

		/**
		 * 32-bit code identifying the particular server or reference clock.
		 * The interpretation depends on the value in the stratum field.
		 */
		enum class ClockSource : uint32_t
		{
			// NTPv4

			/// Geosynchronous Orbit Environment Satellite
			GOES = ('G') | ('O' << 8) | ('E' << 16) | ('S' << 24),
			/// Global Position System
			GPS = ('G') | ('P' << 8) | ('S' << 16),
			/// Galileo Positioning System
			GAL = ('G') | ('A' << 8) | ('L' << 16),
			/// Generic pulse-per-second
			PPS = ('P') | ('P' << 8) | ('S' << 16),
			/// Inter-Range Instrumentation Group
			IRIG = ('I') | ('R' << 8) | ('I' << 16) | ('G' << 24),
			/// LF Radio WWVB Ft. Collins, CO 60 kHz
			WWVB = ('W') | ('W' << 8) | ('V' << 16) | ('B' << 24),
			/// LF Radio DCF77 Mainflingen, DE 77.5 kHz
			DCF = ('D') | ('C' << 8) | ('F' << 16),
			/// LF Radio HBG Prangins, HB 75 kHz
			HBG = ('H') | ('B' << 8) | ('G' << 16),
			/// LF Radio MSF Anthorn, UK 60 kHz
			MSF = ('M') | ('S' << 8) | ('F' << 16),
			/// LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz
			JJY = ('J') | ('J' << 8) | ('Y' << 16),
			/// MF Radio LORAN C station, 100 kHz
			LORC = ('L') | ('O' << 8) | ('R' << 16) | ('C' << 24),
			/// MF Radio Allouis, FR 162 kHz
			TDF = ('T') | ('D' << 8) | ('F' << 16),
			/// HF Radio CHU Ottawa, Ontario
			CHU = ('C') | ('H' << 8) | ('U' << 16),
			/// HF Radio WWV Ft. Collins, CO
			WWV = ('W') | ('W' << 8) | ('V' << 16),
			/// HF Radio WWVH Kauai, HI
			WWVH = ('W') | ('W' << 8) | ('V' << 16) | ('H' << 24),
			/// NIST telephone modem
			NIST = ('N') | ('I' << 8) | ('S' << 16) | ('T' << 24),
			/// NIST telephone modem
			ACTS = ('A') | ('C' << 8) | ('T' << 16) | ('S' << 24),
			/// USNO telephone modem
			USNO = ('U') | ('S' << 8) | ('N' << 16) | ('O' << 24),
			/// European telephone modem
			PTB = ('P') | ('T' << 8) | ('B' << 16),
			/// Multi Reference Sources
			MRS = ('M') | ('R' << 8) | ('S' << 16),
			/// Inter Face Association Changed
			XFAC = ('X') | ('F' << 8) | ('A' << 16) | ('C' << 24),
			/// Step time change
			STEP = ('S') | ('T' << 8) | ('E' << 16) | ('P' << 24),
			/// Google Refid used by Google NTP servers as time4.google.com
			GOOG = ('G') | ('O' << 8) | ('O' << 16) | ('G' << 24),
			/// Meinberg DCF77 with amplitude modulation (Ref:
			/// https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			DCFa = ('D') | ('C' << 8) | ('F' << 16) | ('a' << 24),
			/// Meinberg DCF77 with phase modulation)/pseudo random phase modulation (Ref:
			/// https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			DCFp = ('D') | ('C' << 8) | ('F' << 16) | ('p' << 24),
			/// Meinberg GPS (with shared memory access) (Ref:
			/// https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			GPSs = ('G') | ('P' << 8) | ('S' << 16) | ('s' << 24),
			/// Meinberg GPS (with interrupt based access) (Ref:
			/// https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			GPSi = ('G') | ('P' << 8) | ('S' << 16) | ('i' << 24),
			/// Meinberg GPS/GLONASS (with shared memory access) (Ref:
			/// https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			GLNs = ('G') | ('L' << 8) | ('N' << 16) | ('s' << 24),
			/// Meinberg GPS/GLONASS (with interrupt based access) (Ref:
			/// https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			GLNi = ('G') | ('L' << 8) | ('N' << 16) | ('i' << 24),
			/// Meinberg Undisciplined local clock (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			LCL = ('L') | ('C' << 8) | ('L' << 16),
			/// Meinberg Undisciplined local clock (Ref: https://www.meinbergglobal.com/english/info/ntp-refid.htm)
			LOCL = ('L') | ('O' << 8) | ('C' << 16) | ('L' << 24),

			// NTPv3

			/// DCN routing protocol
			DCN = ('D') | ('C' << 8) | ('N' << 16),
			/// TSP time protocol
			TSP = ('T') | ('S' << 8) | ('P' << 16),
			/// Digital Time Service
			DTS = ('D') | ('T' << 8) | ('S' << 16),
			/// Atomic clock (calibrated)
			ATOM = ('A') | ('T' << 8) | ('O' << 16) | ('M' << 24),
			/// VLF radio (OMEGA, etc.)
			VLF = ('V') | ('L' << 8) | ('F' << 16)
		};

		/**
		 * 32-bit Kiss of Death (KoD) codes
		 */
		enum class KissODeath : uint32_t
		{
			/// The association belongs to a anycast server
			ACST = ('A') | ('C' << 8) | ('S' << 16) | ('T' << 24),
			/// Server authentication failed
			AUTH = ('A') | ('U' << 8) | ('T' << 16) | ('H' << 24),
			/// Autokey sequence failed
			AUTO = ('A') | ('U' << 8) | ('T' << 16) | ('O' << 24),
			/// The association belongs to a broadcast server
			BCST = ('B') | ('C' << 8) | ('S' << 16) | ('T' << 24),
			/// Cryptographic authentication or identification failed
			CRYP = ('C') | ('R' << 8) | ('Y' << 16) | ('P' << 24),
			/// Access denied by remote server
			DENY = ('D') | ('E' << 8) | ('N' << 16) | ('Y' << 24),
			/// Lost peer in symmetric mode
			DROP = ('D') | ('R' << 8) | ('O' << 16) | ('P' << 24),
			/// Access denied due to local policy
			RSTR = ('R') | ('S' << 8) | ('T' << 16) | ('R' << 24),
			/// The association has not yet synchronized for the first time
			INIT = ('I') | ('N' << 8) | ('I' << 16) | ('T' << 24),
			/// The association belongs to a manycast server
			MCST = ('M') | ('C' << 8) | ('S' << 16) | ('T' << 24),
			/// No key found.  Either the key was never installed or is not trusted
			NKEY = ('N') | ('K' << 8) | ('E' << 16) | ('Y' << 24),
			/// Rate exceeded.  The server has temporarily denied access because the client exceeded the rate threshold
			RATE = ('R') | ('A' << 8) | ('T' << 16) | ('E' << 24),
			/// Somebody is tinkering with the association from a remote host running ntpdc.  Not to worry unless some
			/// rascal has stolen your keys
			RMOT = ('R') | ('M' << 8) | ('O' << 16) | ('T' << 24),
			/// A step change in system time has occurred, but the association has not yet resynchronized
			STEP = ('S') | ('T' << 8) | ('E' << 16) | ('P' << 24),
		};

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NtpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, NTP)
		{}

		/**
		 * Empty c'tor
		 */
		NtpLayer();

		/**
		 * @return The leap indicator
		 */
		LeapIndicator getLeapIndicator() const;

		/**
		 * Set the leap indicator
		 */
		void setLeapIndicator(LeapIndicator val);

		/**
		 * @return The version of NTP
		 */
		uint8_t getVersion() const;

		/**
		 * Set the version of NTP
		 */
		void setVersion(uint8_t val);

		/**
		 * @return The mode value
		 */
		Mode getMode() const;

		/**
		 * @return The mode as string
		 */
		std::string getModeString() const;

		/**
		 * Set the mode
		 */
		void setMode(Mode val);

		/**
		 * @return The value of stratum
		 */
		uint8_t getStratum() const;

		/**
		 * Set the value of stratum
		 */
		void setStratum(uint8_t val);

		/**
		 * @return The value of poll interval in log2 seconds
		 */
		int8_t getPollInterval() const;

		/**
		 * Set the value of poll interval
		 * @param[in] val Poll interval in log2 seconds
		 */
		void setPollInterval(int8_t val);

		/**
		 * @return The value of poll interval in seconds
		 */
		double getPollIntervalInSecs() const;

		/**
		 * @return The value of precision in log2 seconds
		 */
		int8_t getPrecision() const;

		/**
		 * Set the value of precision
		 * @param[in] val Precision in log2 seconds
		 */
		void setPrecision(int8_t val);

		/**
		 * @return The value of precision in seconds
		 */
		double getPrecisionInSecs() const;

		/**
		 * @return The value of root delay in NTP short format
		 */
		uint32_t getRootDelay() const;

		/**
		 * Set the value of root delay
		 * @param[in] val Root delay in NTP short format
		 */
		void setRootDelay(uint32_t val);

		/**
		 * @return The value of root delay in seconds
		 */
		double getRootDelayInSecs() const;

		/**
		 * Set the value of root delay
		 * @param[in] val Root delay in seconds
		 */
		void setRootDelayInSecs(double val);

		/**
		 * @return The value of root dispersion in NTP short format
		 */
		uint32_t getRootDispersion() const;

		/**
		 * Set the value of root delay
		 * @param[in] val Root dispersion in NTP short format
		 */
		void setRootDispersion(uint32_t val);

		/**
		 * @return The value of root dispersion in seconds
		 */
		double getRootDispersionInSecs() const;

		/**
		 * Set the value of root dispersion
		 * @param[in] val Root dispersion in seconds
		 */
		void setRootDispersionInSecs(double val);

		/**
		 * @return The value of reference identifier
		 */
		uint32_t getReferenceIdentifier() const;

		/**
		 * Set the value of reference identifier
		 * @param[in] val Value of the reference identifier as IPv4 address
		 */
		void setReferenceIdentifier(IPv4Address val);

		/**
		 * Set the value of reference identifier
		 * @param[in] val Value of the reference identifier as ClockSource
		 */
		void setReferenceIdentifier(ClockSource val);

		/**
		 * Set the value of reference identifier
		 * @param[in] val Value of the reference identifier as Kiss-O-Death code
		 */
		void setReferenceIdentifier(KissODeath val);

		/**
		 * @return The value of reference identifier as a string. String representation of NTP clock source if stratum
		 * is 1, IPv4 address or MD5 hash of first four octets of IPv6
		 */
		std::string getReferenceIdentifierString() const;

		/**
		 * @return The value of reference timestamp in NTP timestamp format
		 */
		uint64_t getReferenceTimestamp() const;

		/**
		 * Set the value of reference timestamp
		 * @param[in] val Timestamp in NTP timestamp format
		 */
		void setReferenceTimestamp(uint64_t val);

		/**
		 * @return The value of reference timestamp in seconds from Unix Epoch (1 Jan 1970)
		 */
		double getReferenceTimestampInSecs() const;

		/**
		 * Set the value of reference timestamp
		 * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
		 */
		void setReferenceTimestampInSecs(double val);

		/**
		 * @return The reference timestamp value as readable string in ISO8601 format
		 */
		std::string getReferenceTimestampAsString();

		/**
		 * @return The value of origin timestamp in NTP timestamp format
		 */
		uint64_t getOriginTimestamp() const;

		/**
		 * Set the value of origin timestamp
		 * @param[in] val Value in NTP timestamp format
		 */
		void setOriginTimestamp(uint64_t val);

		/**
		 * @return The value of origin timestamp in seconds from Unix Epoch (1 Jan 1970)
		 */
		double getOriginTimestampInSecs() const;

		/**
		 * Set the value of origin timestamp
		 * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
		 */
		void setOriginTimestampInSecs(double val);

		/**
		 * @return the origin timestamp value as readable string in ISO8601 format
		 */
		std::string getOriginTimestampAsString();

		/**
		 * @return The value of receive timestamp in NTP timestamp format
		 */
		uint64_t getReceiveTimestamp() const;

		/**
		 * Set the value of receive timestamp
		 * @param[in] val Value in NTP timestamp format
		 */
		void setReceiveTimestamp(uint64_t val);

		/**
		 * @return The value of receive timestampin seconds from Unix Epoch (1 Jan 1970)
		 */
		double getReceiveTimestampInSecs() const;

		/**
		 * Set the value of receive timestamp
		 * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
		 */
		void setReceiveTimestampInSecs(double val);

		/**
		 * @return The receive timestamp value as readable string in ISO8601 format
		 */
		std::string getReceiveTimestampAsString();

		/**
		 * @return The value of transmit timestamp in NTP timestamp format
		 */
		uint64_t getTransmitTimestamp() const;

		/**
		 * Set the value of transmit timestamp
		 * @param[in] val Value in NTP timestamp format
		 */
		void setTransmitTimestamp(uint64_t val);

		/**
		 * @return The value of transmit timestamp in seconds from Unix Epoch (1 Jan 1970)
		 */
		double getTransmitTimestampInSecs() const;

		/**
		 * Set the value of transmit timestamp
		 * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
		 */
		void setTransmitTimestampInSecs(double val);

		/**
		 * @return The transmit timestamp value as readable string in ISO8601 format
		 */
		std::string getTransmitTimestampAsString();

		/**
		 * @return Returns the key identifier if exists, returns 0 on unsupported NTP version or key identifier not
		 * found
		 */
		uint32_t getKeyID() const;

		/**
		 * @return Get the digest value as hexadecimal string, empty string on unsupported version
		 */
		std::string getDigest() const;

		/**
		 * Convert NTP short format to seconds from the Unix Epoch
		 *
		 * @param[in] val Value in NTP short format
		 * @return Value in seconds from Unix Epoch (1 Jan 1970)
		 */
		static double convertFromShortFormat(const uint32_t val);

		/**
		 * Convert NTP timestamp format to seconds from the Unix Epoch
		 *
		 * @param[in] val Value in NTP timestamp format
		 * @return Value in seconds from Unix Epoch (1 Jan 1970)
		 */
		static double convertFromTimestampFormat(const uint64_t val);

		/**
		 * Convert seconds from the Unix Epoch to NTP short format
		 *
		 * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
		 * @return Value in NTP short format
		 */
		static uint32_t convertToShortFormat(const double val);

		/**
		 * Convert seconds from the Unix Epoch to NTP timestamp format
		 *
		 * @param[in] val Value in seconds from Unix Epoch (1 Jan 1970)
		 * @return Value in NTP timestamp format
		 */
		static uint64_t convertToTimestampFormat(const double val);

		/**
		 * A static method to convert timestamp value to ISO8601 date time format
		 * @param[in] timestamp Value in seconds from the Unix Epoch
		 * @return std::string ISO8601 formatted string
		 */
		static std::string convertToIsoFormat(const double timestamp);

		/**
		 * A static method to convert timestamp value to ISO8601 date time format
		 * @param[in] timestampInNTPformat Value in NTP timestamp format
		 * @return std::string ISO8601 formatted string
		 */
		static std::string convertToIsoFormat(const uint64_t timestampInNTPformat);

		/**
		 * A static method that takes a byte array and detects whether it is a NTP message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as NTP message
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);

		/**
		 * A static method that checks whether the port is considered as NTP
		 * @param[in] port The port number to be checked
		 */
		static bool isNTPPort(uint16_t port)
		{
			return port == 123;
		}

		// overridden methods

		/// Parses the next layer. NTP is the always last so does nothing for this layer
		void parseNextLayer()
		{}

		/**
		 * @return Get the size of the layer (Including the extension and authentication fields if exists)
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		/// Does nothing for this layer
		void computeCalculateFields()
		{}

		/**
		 * @return The OSI layer level of NTP (Application Layer).
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};

}  // namespace vanhooks::net
// ---- end NtpLayer.h ----

// ---- begin SSHLayer.h ----
/**
 * @file
 * This file introduces classes and structures that represent the SSH (Secure Shell) protocol.
 *
 * An overview of this protocol can be found here: https://en.wikipedia.org/wiki/Ssh_(Secure_Shell)
 *
 * For more details please refer to RFC 4253: https://tools.ietf.org/html/rfc4253
 *
 * These current implementation supports parsing of SSH packets when possible (meaning when they are not encrypted).
 * Creation and editing of SSH packets is currently __not supported__.
 *
 * SSH typically uses TCP port 22 so VanHooks assumes all traffic on this port is SSH traffic.
 * VanHooks uses some heuristics to determine the type of the SSH message (which will be covered later).
 * If it doesn't find a match to one of the other SSH messages, it assumes it is an encrypted SSH message.
 *
 * Following is an overview of the SSH protocol classes currently supported in VanHooks. They cover the different
 * messages of the SSH protocol:
 *
  @verbatim

                             +----------------------------+      SSH version identification
                         +---|  SSHIdentificationMessage  | ===> as described here:
                         |   +----------------------------+      https://tools.ietf.org/html/rfc4253#section-4.2
                         |
  +------------+         |   +----------------------------+      SSH handshake message
  |  SSHLayer  |---------+---|  SSHHandshakeMessage       | ===> which is typically one of the messages described here:
  | (abstract) |         |   +----------------------------+      https://tools.ietf.org/html/rfc4253#section-12
  +------------+         |                 |
                         |                 |     +----------------------------+
                         |                 +-----|  SSHKeyExchangeInitMessage | ===> SSH Key Exchange message
                         |                       +----------------------------+      as described here:
                         |                                                 https://tools.ietf.org/html/rfc4253#section-7
                         |
                         |   +----------------------------+
                         +---|  SSHEncryptedMessage       | ===> An encrypted SSH message
                             +----------------------------+

  @endverbatim

  * The following points describe the heuristics for deciding the message type for each packet:
  * 1. If the data starts with the characters "SSH-" and ends with "\n" (or "\r\n") it's assumed the message is of type
  *    vanhooks::net::SSHIdentificationMessage
  * 2. Try to determine if this is a non-encrypted SSH handshake message:
  *    - Look at the first 4 bytes of the data which may contain the packet length and see if the value is smaller of
  *      equal than the entire layer length.
  *    - The next byte contains the padding length, check if it's smaller or equal than the packet length
  *    - The next byte contains the message type, check if the value is a valid message type as described in:
  *      <https://tools.ietf.org/html/rfc4253#section-12>
  *
  *    If all of these condition are met, this message is either vanhooks::net::SSHKeyExchangeInitMessage (if message type is
  *    vanhooks::net::SSHHandshakeMessage#SSH_MSG_KEX_INIT) or vanhooks::net::SSHHandshakeMessage (for all other message types)
  * 3. If non of these conditions are met, it is assumed this is an encrypted message (vanhooks::net::SSHEncryptedMessage)
 */

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class SSHLayer
	 * This is the base class for the SSH layer. It is an abstract class that cannot be instantiated.
	 * It holds some common functionality, but its most important method is createSSHMessage()
	 * which takes raw data and creates an SSH message according to the heuristics described
	 * in the SSHLayer.h file description
	 */
	class SSHLayer : public Layer
	{
	public:
		/**
		 * A static method that takes raw packet data and uses the heuristics described in the
		 * SSHLayer.h file description to create an SSH layer instance. This method assumes the data is
		 * indeed SSH data and not some other arbitrary data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return An instance of one of the classes that inherit SSHLayer as described in the
		 * SSHLayer.h file description
		 */
		static SSHLayer* createSSHMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A static method that takes src and dst ports and determines whether it's SSH traffic or not.
		 * @param[in] portSrc The source TCP port to examine
		 * @param[in] portDst The dest TCP port to examine
		 * @return Currently the implementation is very simple and returns "true" if either src or dst ports
		 * are equal to 22, "false" otherwise
		 */
		static bool isSSHPort(uint16_t portSrc, uint16_t portDst)
		{
			return portSrc == 22 || portDst == 22;
		}

		// implement abstract methods

		/**
		 * Several SSH records can reside in a single packets. This method examins the remaining data and creates
		 * additional SSH records if applicable
		 */
		void parseNextLayer();

		/**
		 * Does nothing for this layer
		 */
		void computeCalculateFields()
		{}

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

	protected:
		// protected c'tor, this class cannot be instantiated
		SSHLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, SSH)
		{}

	private:
		// this layer supports only parsing
		SSHLayer();
	};

	/**
	 * @class SSHIdentificationMessage
	 * A class that represents SSH identification message as described in RFC 4253:
	 * <https://tools.ietf.org/html/rfc4253#section-4.2>
	 *
	 * The message content is typically a string that contains the protocol version, software version and a few more
	 * details. This string can be retrieved using the getIdentificationMessage() method
	 */
	class SSHIdentificationMessage : public SSHLayer
	{
	public:
		/**
		 * @return The SSH identification message which is typically the content of this message
		 */
		std::string getIdentificationMessage();

		/**
		 * A static method that takes raw data and tries to parse it as an SSH identification message using the
		 * heuristics described in the SSHLayer.h file description. It returns a SSHIdentificationMessage instance if
		 * such a message can be identified or nullptr otherwise.
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return An instance of SSHIdentificationMessage or nullptr if this is not an identification message
		 */
		static SSHIdentificationMessage* tryParse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/**
		 * @return The size of the identification message
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		std::string toString() const;

	private:
		// this layer supports only parsing
		SSHIdentificationMessage();

		// private c'tor, this class cannot be instantiated
		SSHIdentificationMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSHLayer(data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class SSHHandshakeMessage
	 * A class representing all of the non-encrypted SSH handshake messages.
	 * An handshake message typically has the following structure:
	 *
	 @verbatim
	 0         1         2         3         4         5         6
	 +---------+---------+---------+---------+---------+---------+-----------     ---------+
	 |            Packet Length              | Padding | Message |  Message  ....  Padding |
	 |                                       | Length  |  Type   |  Content  ....          |
	 +---------------------------------------+---------+---------+-----------     ---------+
	 @endverbatim
	 *
	 * The first 4 bytes hold the packet length, followed by 1 byte that holds the padding length (which comes at the
	 * end of the message), then 1 byte that holds the message type (which can be of type
	 * SSHHandshakeMessage#SSHHandshakeMessageType) and then the message content. At the end of the content there is
	 * typically padding.
	 *
	 * This class provides access to all of these values. The message content itself is not parse with the exception of
	 * SSHKeyExchangeInitMessage
	 * which inherits from this class and provides parsing of the Key Exchange Init message.
	 */
	class SSHHandshakeMessage : public SSHLayer
	{
	public:
		/**
		 * An enum that represents SSH non-encrypted message types
		 */
		enum SSHHandshakeMessageType
		{
			/** Key Exchange Init message */
			SSH_MSG_KEX_INIT = 20,
			/** New Keys message */
			SSH_MSG_NEW_KEYS = 21,
			/** Diffie-Hellman Key Exchange Init message */
			SSH_MSG_KEX_DH_INIT = 30,
			/**  message */
			SSH_MSG_KEX_DH_REPLY = 31,
			/** Diffie-Hellman Group Exchange Init message */
			SSH_MSG_KEX_DH_GEX_INIT = 32,
			/** "Diffie-Hellman Group Exchange Reply message */
			SSH_MSG_KEX_DH_GEX_REPLY = 33,
			/** Diffie-Hellman Group Exchange Request message */
			SSH_MSG_KEX_DH_GEX_REQUEST = 34,
			/** Unknown message */
			SSH_MSG_UNKNOWN = 999
		};

		/**
		 * @return The message type
		 */
		SSHHandshakeMessageType getMessageType() const;

		/**
		 * @return A string representation of the message type
		 */
		std::string getMessageTypeStr() const;

		/**
		 * @return A raw byte stream of the message content
		 */
		uint8_t* getSSHHandshakeMessage() const;

		/**
		 * @return The message content length in [bytes] which is calculated by the overall packet length
		 * minus the message header (which includes packet length, padding length and message type) and
		 * minus the padding bytes
		 */
		size_t getSSHHandshakeMessageLength() const;

		/**
		 * @return The padding length in [bytes]
		 */
		size_t getPaddingLength() const;

		/**
		 * A static method that takes raw packet data and uses some heuristics described in the
		 * SSHLayer.h file description to parse it as SSH handshake message instance
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return Upon successful parsing the return value would be an instance of SSHKeyExchangeInitMessage
		 * for Key Exchange Init message or SSHHandshakeMessage for any other message type. If parsing fails nullptr
		 * will be returned
		 */
		static SSHHandshakeMessage* tryParse(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/**
		 * @return The size of the SSH handshake message including the padding and message header
		 */
		size_t getHeaderLen() const;

		std::string toString() const;

	protected:
#pragma pack(push, 1)
		/**
		 * An internal struct representing the SSH handshake message header
		 */
		struct ssh_message_base
		{
			uint32_t packetLength;
			uint8_t paddingLength;
			uint8_t messageCode;
		};
#pragma pack(pop)

		// this layer supports only parsing
		SSHHandshakeMessage();

		// private c'tor, this class cannot be instantiated
		SSHHandshakeMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSHLayer(data, dataLen, prevLayer, packet)
		{}

		ssh_message_base* getMsgBaseHeader() const
		{
			return (ssh_message_base*)m_Data;
		}
	};

	/**
	 * @class SSHKeyExchangeInitMessage
	 * A class representing the SSH Key Exchange Init message. This is a non-encrypted message that contains information
	 * about the algorithms used for key exchange, encryption, MAC and compression. This class provides methods to
	 * access these details
	 */
	class SSHKeyExchangeInitMessage : public SSHHandshakeMessage
	{
	public:
		/**
		 * A c'tor for this class that accepts raw message data. Please avoid using it as it's used internally
		 * when parsing SSH handshake messages in SSHHandshakeMessage#tryParse()
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSHKeyExchangeInitMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Each SSH Key Exchange Init message contains a random 16-byte value generated by the sender.
		 * This method returns a pointer to this 16-byte cookie. To get the value as a hex string
		 * please refer to getCookieAsHexStream()
		 * @return A pointer to the 16-byte cookie value or nullptr if the message is malformed
		 */
		uint8_t* getCookie();

		/**
		 * Each SSH Key Exchange Init message contains a random 16-byte value generated by the sender.
		 * This method returns the 16-byte cookie as a hex stream. To get the raw data please refer to
		 * getCookie()
		 * @return A hex stream of the 16-byte cookie value or an empty string if the message is malformed
		 */
		std::string getCookieAsHexStream();

		/**
		 * @return A comma-separated list of the key exchange algorithms used in this session.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getKeyExchangeAlgorithms()
		{
			return getFieldValue(0);
		}

		/**
		 * @return A comma-separated list of the algorithms supported for the server host key.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getServerHostKeyAlgorithms()
		{
			return getFieldValue(1);
		}

		/**
		 * @return A comma-separated list of acceptable symmetric encryption algorithms (also known as ciphers)
		 * from the client to the server. Can be empty if the value is missing or the message is malformed
		 */
		std::string getEncryptionAlgorithmsClientToServer()
		{
			return getFieldValue(2);
		}

		/**
		 * @return A comma-separated list of acceptable symmetric encryption algorithms (also known as ciphers)
		 * from the server to the client. Can be empty if the value is missing or the message is malformed
		 */
		std::string getEncryptionAlgorithmsServerToClient()
		{
			return getFieldValue(3);
		}

		/**
		 * @return A comma-separated list of acceptable MAC algorithms from the client to the server.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getMacAlgorithmsClientToServer()
		{
			return getFieldValue(4);
		}

		/**
		 * @return A comma-separated list of acceptable MAC algorithms from the server to the client.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getMacAlgorithmsServerToClient()
		{
			return getFieldValue(5);
		}

		/**
		 * @return A comma-separated list of acceptable compression algorithms from the client to the server.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getCompressionAlgorithmsClientToServer()
		{
			return getFieldValue(6);
		}

		/**
		 * @return A comma-separated list of acceptable compression algorithms from the server to the client.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getCompressionAlgorithmsServerToClient()
		{
			return getFieldValue(7);
		}

		/**
		 * @return A comma-separated list of language tags from the client to the server.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getLanguagesClientToServer()
		{
			return getFieldValue(8);
		}

		/**
		 * @return A comma-separated list of language tags from the server to the client.
		 * Can be empty if the value is missing or the message is malformed
		 */
		std::string getLanguagesServerToClient()
		{
			return getFieldValue(9);
		}

		/**
		 * @return Indicates whether a guessed key exchange packet follows. If a
		 * guessed packet will be sent, the return value is true. If no guessed
		 * packet will be sent or if this value is missing, the return value is false.
		 */
		bool isFirstKexPacketFollows();

	private:
		size_t m_FieldOffsets[11];
		bool m_OffsetsInitialized;

		void parseMessageAndInitOffsets();

		std::string getFieldValue(int fieldOffsetIndex);
	};

	/**
	 * @class SSHEncryptedMessage
	 * A class representing an SSH encrypted message. In such messages there is very little information to extract from
	 * the packet, hence this class doesn't expose any methods or getters, other than the ones inherited from parent
	 * classes.
	 *
	 * It is assumed that any SSH message which does not fit to any of the other SSH message types, according to the
	 * heuristics described in the SSHLayer.h file description, is considered as an encrypted message.
	 */
	class SSHEncryptedMessage : public SSHLayer
	{
	public:
		/**
		 * A c'tor for this class that accepts raw message data. Please avoid using it as it's used internally
		 * when parsing SSH messages in SSHLayer#createSSHMessage()
		 */
		SSHEncryptedMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSHLayer(data, dataLen, prevLayer, packet)
		{}

		// implement abstract methods

		/**
		 * @return The size of the message which is equal to the size of the layer
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		std::string toString() const;
	};

}  // namespace vanhooks::net
// ---- end SSHLayer.h ----

