#pragma once

// ===== Consolidated header: TextProtocols.h =====
// Merges: TextBasedProtocol, SingleCommandTextProtocol, HttpLayer, SipLayer, SdpLayer, FtpLayer, SmtpLayer, TelnetLayer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "PacketCore.h"
#include "Common.h"

// ---- begin TextBasedProtocol.h ----
#include <map>

/// @file

namespace vanhooks::net
{

/** End of header */
#define VH_END_OF_TEXT_BASED_PROTOCOL_HEADER ""

	class TextBasedProtocolMessage;

	// -------- Class HeaderField -----------------

	/**
	 * @class HeaderField
	 * A wrapper class for each text-based-protocol header field, e.g "Host", "Cookie", "Content-Length", "Via",
	 * "Call-ID", etc. Each field contains a name (e.g "Host") and a value (e.g "www.wikipedia.org"). The user can get
	 * and set both of them through dedicated methods. The separator between header fields is either CRLF ("\r\n\") or
	 * LF ("\n") in more rare cases, which means every HeaderField instance is responsible for wrapping and parsing a
	 * header field from the previous CRLF (not inclusive) until the next CRLF/LF (inclusive) A special case is with the
	 * end of a header, meaning 2 consecutive CRLFs ("\r\n\r\n") or consecutive LFs ("\n\n"). VanHooks treats the
	 * first CRLF/LF as part of the last field in the header, and the second CRLF is an HeaderField instance of its own
	 * which name and values are an empty string ("") or vanhooks::net::VH_END_OF_TEXT_BASED_PROTOCOL_HEADER
	 */
	class HeaderField
	{
		friend class TextBasedProtocolMessage;

	public:
		~HeaderField();

		/**
		 * A copy constructor that creates a new instance out of an existing HeaderField instance. The copied instance
		 * will not have shared resources with the original instance, meaning all members and properties are copied
		 * @param[in] other The original instance to copy from
		 */
		HeaderField(const HeaderField& other);

		/**
		 * Assignment operator for this class. This method copies the data from the other instance and will not share
		 * any resources with it. Also, if the instance already contains data it will be deleted or zeroed
		 * @param[in] other The instance to assign from
		 * @return A reference to the assignee
		 */
		HeaderField& operator=(const HeaderField& other);

		/**
		 * @return The field length in bytes, meaning count of all characters from the previous CRLF (not inclusive)
		 * until the next CRLF (inclusive) For example: the field "Host: www.wikipedia.org\r\n" will have the length of
		 * 25
		 */
		size_t getFieldSize() const
		{
			return m_FieldSize;
		}

		/**
		 * @return The field name as string. Notice the return data is copied data, so changing it won't change the
		 * packet data
		 */
		std::string getFieldName() const;

		/**
		 * @return The field value as string. Notice the return data is copied data, so changing it won't change the
		 * packet data
		 */
		std::string getFieldValue() const;

		/**
		 * A setter for field value
		 * @param[in] newValue The new value to set to the field. Old value will be deleted
		 * @return True if setting the value was completed successfully, false otherwise
		 */
		bool setFieldValue(const std::string& newValue);

		/**
		 * Get an indication whether the field is a field that ends the header (meaning contain only CRLF - see class
		 * explanation)
		 * @return True if this is a end-of-header field, false otherwise
		 */
		bool isEndOfHeader() const
		{
			return m_IsEndOfHeaderField;
		}

	private:
		HeaderField(const std::string& name, const std::string& value, char nameValueSeparator,
		            bool spacesAllowedBetweenNameAndValue);
		HeaderField(TextBasedProtocolMessage* TextBasedProtocolMessage, int offsetInMessage, char nameValueSeparator,
		            bool spacesAllowedBetweenNameAndValue);

		char* getData() const;
		void setNextField(HeaderField* nextField);
		HeaderField* getNextField() const;
		void initNewField(const std::string& name, const std::string& value);
		void attachToTextBasedProtocolMessage(TextBasedProtocolMessage* message, int fieldOffsetInMessage);

		uint8_t* m_NewFieldData;
		TextBasedProtocolMessage* m_TextBasedProtocolMessage;
		int m_NameOffsetInMessage;
		size_t m_FieldNameSize;
		int m_ValueOffsetInMessage;
		size_t m_FieldValueSize;
		size_t m_FieldSize;
		HeaderField* m_NextField;
		bool m_IsEndOfHeaderField;
		char m_NameValueSeparator;
		bool m_SpacesAllowedBetweenNameAndValue;
	};

	// -------- Class TextBasedProtocolMessage -----------------

	/**
	 * @class TextBasedProtocolMessage
	 * An abstract base class that wraps text-based-protocol header layers (both requests and responses). It is the base
	 * class for all those layers. This class is not meant to be instantiated, hence the protected c'tor
	 */
	class TextBasedProtocolMessage : public Layer
	{
		friend class HeaderField;

	public:
		~TextBasedProtocolMessage();

		/**
		 * Get a pointer to a header field by name. The search is case insensitive, meaning if a field with name "Host"
		 * exists and the fieldName parameter is "host" (all letter are lower case), this method will return a pointer
		 * to "Host" field
		 * @param[in] fieldName The field name
		 * @param[in] index Optional parameter. If the field name appears more than once, this parameter will indicate
		 * which field to get. The default value is 0 (get the first appearance of the field name as appears on the
		 * packet)
		 * @return A pointer to an HeaderField instance, or nullptr if field doesn't exist
		 */
		HeaderField* getFieldByName(std::string fieldName, int index = 0) const;

		/**
		 * @return A pointer to the first header field exists in this message, or nullptr if no such field exists
		 */
		HeaderField* getFirstField() const
		{
			return m_FieldList;
		}

		/**
		 * Get the field which appears after a certain field
		 * @param[in] prevField A pointer to the field
		 * @return The field after prevField or nullptr if prevField is the last field. If prevField is nullptr, this
		 * method will return nullptr
		 */
		HeaderField* getNextField(HeaderField* prevField) const
		{
			if (prevField != nullptr)
				return prevField->getNextField();
			else
				return nullptr;
		}

		/**
		 * @return The number of header fields currently in the layer (not including CRLF at the end of the header)
		 */
		int getFieldCount() const;

		/**
		 * Add a new header field to this message. This field will be added last (before the end-of-header field)
		 * @param[in] fieldName The field name
		 * @param[in] fieldValue The field value
		 * @return A pointer to the newly created header field, or nullptr if the field could not be created
		 */
		virtual HeaderField* addField(const std::string& fieldName, const std::string& fieldValue);

		/**
		 * Add a new header field to this message. This field will be added last (before the end-of-header field)
		 * @param[in] newField The header field to add
		 * @return A pointer to the newly created header field, or nullptr if the field could not be created
		 */
		virtual HeaderField* addField(const HeaderField& newField);

		/**
		 * Add the special end-of-header field (see the explanation in HeaderField)
		 * @return A pointer to the newly created header field, or nullptr if the field could not be created
		 */
		HeaderField* addEndOfHeader();

		/**
		 * Insert a new field after an existing field
		 * @param[in] prevField A pointer to the existing field. If it's nullptr the new field will be added as first
		 * field
		 * @param[in] fieldName The field name
		 * @param[in] fieldValue The field value
		 * @return A pointer to the newly created header field, or nullptr if the field could not be created
		 */
		virtual HeaderField* insertField(HeaderField* prevField, const std::string& fieldName,
		                                 const std::string& fieldValue);

		/**
		 * Insert a new field after an existing field
		 * @param[in] prevFieldName A name of an existing field. If the field doesn't exist nullptr will be returned.
		 * If field name is empty ('') the new field will be added as first field
		 * @param[in] fieldName The field name
		 * @param[in] fieldValue The field value
		 * @return A pointer to the newly created header field, or nullptr if the field could not be created
		 */
		virtual HeaderField* insertField(std::string prevFieldName, const std::string& fieldName,
		                                 const std::string& fieldValue);

		/**
		 * Insert a new field after an existing field
		 * @param[in] prevField A pointer to the existing field
		 * @param[in] newField The header field to add
		 * @return A pointer to the newly created header field, or nullptr if the field could not be created
		 */
		virtual HeaderField* insertField(HeaderField* prevField, const HeaderField& newField);

		/**
		 * Remove a field from the message
		 * @param[in] fieldToRemove A pointer to the field that should be removed
		 * @return True if the field was removed successfully, or false otherwise (for example: if fieldToRemove is
		 * nullptr, if it doesn't exist in the message, or if the removal failed)
		 */
		bool removeField(HeaderField* fieldToRemove);

		/**
		 * Remove a field from the message
		 * @param[in] fieldName The name of the field that should be removed
		 * @param[in] index Optional parameter. If the field name appears more than once, this parameter will indicate
		 * which field to remove. The default value is 0 (remove the first appearance of the field name as appears on
		 * the packet)
		 * @return True if the field was removed successfully, or false otherwise (for example: if fieldName doesn't
		 * exist in the message, or if the removal failed)
		 */
		bool removeField(std::string fieldName, int index = 0);

		/**
		 * Indicate whether the header is complete (ending with end-of-header "\r\n\r\n" or "\n\n") or spread over more
		 * packets
		 * @return True if the header is complete or false if not
		 */
		bool isHeaderComplete() const;

		// implement Layer's abstract methods

		/**
		 * Currently set only PayloadLayer for the rest of the data
		 */
		virtual void parseNextLayer();

		/**
		 * @return The message length
		 */
		size_t getHeaderLen() const;

		/**
		 * Does nothing for this class
		 */
		virtual void computeCalculateFields();

	protected:
		TextBasedProtocolMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet,
		                         ProtocolType protocol);
		TextBasedProtocolMessage() : m_FieldList(nullptr), m_LastField(nullptr), m_FieldsOffset(0)
		{}

		// copy c'tor
		TextBasedProtocolMessage(const TextBasedProtocolMessage& other);
		TextBasedProtocolMessage& operator=(const TextBasedProtocolMessage& other);

		void copyDataFrom(const TextBasedProtocolMessage& other);

		void parseFields();
		void shiftFieldsOffset(HeaderField* fromField, int numOfBytesToShift);

		// abstract methods
		virtual char getHeaderFieldNameValueSeparator() const = 0;
		virtual bool spacesAllowedBetweenHeaderFieldNameAndValue() const = 0;

		HeaderField* m_FieldList;
		HeaderField* m_LastField;
		int m_FieldsOffset;
		std::multimap<std::string, HeaderField*> m_FieldNameToFieldMap;
	};

}  // namespace vanhooks::net
// ---- end TextBasedProtocol.h ----

// ---- begin SingleCommandTextProtocol.h ----
#include <sstream>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * Class for single command text based protocol (FTP, SMTP) messages
	 */
	class SingleCommandTextProtocol : public Layer
	{
	private:
		size_t getArgumentFieldOffset() const;
		void setDelimiter(bool hyphen);
		bool hyphenRequired(const std::string& value);

	protected:
		SingleCommandTextProtocol(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet,
		                          ProtocolType protocol)
		    : Layer(data, dataLen, prevLayer, packet, protocol) {};

		SingleCommandTextProtocol(const std::string& command, const std::string& option, ProtocolType protocol);

		bool setCommandInternal(std::string value);
		bool setCommandOptionInternal(std::string value);

		std::string getCommandInternal() const;
		std::string getCommandOptionInternal() const;

	public:
		/**
		 * Checks if the current message is a multi-line reply. Multi-line messages are indicated with a Hyphen (-)
		 * immediately after reply code.
		 * @return true If this is a multi-line reply
		 * @return false Otherwise
		 */
		bool isMultiLine() const;

		/**
		 * A static method that takes a byte array and detects whether it is a single command text based message.
		 * All single command text based message terminated with single "\r\n".
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as single command text based message
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize);
	};
}  // namespace vanhooks::net
// ---- end SingleCommandTextProtocol.h ----

// ---- begin HttpLayer.h ----
#include <string>
#include <exception>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * An enum for HTTP version
	 */
	enum HttpVersion
	{
		/** HTTP/0.9 */
		ZeroDotNine,
		/** HTTP/1.0 */
		OneDotZero,
		/** HTTP/1.1 */
		OneDotOne,
		/** Unknown HTTP version */
		HttpVersionUnknown
	};

	// some popular HTTP fields

	/** Host field */
#define VH_HTTP_HOST_FIELD "Host"
	/** Connection field */
#define VH_HTTP_CONNECTION_FIELD "Connection"
	/** User-Agent field */
#define VH_HTTP_USER_AGENT_FIELD "User-Agent"
	/** Referer field */
#define VH_HTTP_REFERER_FIELD "Referer"
	/** Accept field */
#define VH_HTTP_ACCEPT_FIELD "Accept"
	/** Accept-Encoding field */
#define VH_HTTP_ACCEPT_ENCODING_FIELD "Accept-Encoding"
	/** Accept-Language field */
#define VH_HTTP_ACCEPT_LANGUAGE_FIELD "Accept-Language"
	/** Cookie field */
#define VH_HTTP_COOKIE_FIELD "Cookie"
	/** Content-Length field */
#define VH_HTTP_CONTENT_LENGTH_FIELD "Content-Length"
	/** Content-Encoding field */
#define VH_HTTP_CONTENT_ENCODING_FIELD "Content-Encoding"
	/** Content-Type field */
#define VH_HTTP_CONTENT_TYPE_FIELD "Content-Type"
	/** Transfer-Encoding field */
#define VH_HTTP_TRANSFER_ENCODING_FIELD "Transfer-Encoding"
	/** Server field */
#define VH_HTTP_SERVER_FIELD "Server"

	// -------- classes to be defined later -----------------

	class HttpRequestFirstLine;
	class HttpResponseFirstLine;

	// -------- Class HttpMessage -----------------

	/**
	 * @class HttpMessage
	 * Represents a general HTTP message. It's an abstract class and cannot be instantiated. It's inherited by
	 * HttpRequestLayer and HttpResponseLayer
	 */
	class HttpMessage : public TextBasedProtocolMessage
	{
	public:
		virtual ~HttpMessage()
		{}

		/**
		 * A static method that checks whether the port is considered as HTTP
		 * @param[in] port The port number to be checked
		 * @return True if the port matches those associated with the HTTP protocol
		 */
		static bool isHttpPort(uint16_t port)
		{
			return port == 80 || port == 8080;
		}

		// overridden methods

		virtual HeaderField* addField(const std::string& fieldName, const std::string& fieldValue);
		virtual HeaderField* addField(const HeaderField& newField);
		virtual HeaderField* insertField(HeaderField* prevField, const std::string& fieldName,
		                                 const std::string& fieldValue);
		virtual HeaderField* insertField(HeaderField* prevField, const HeaderField& newField);

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

	protected:
		HttpMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol)
		    : TextBasedProtocolMessage(data, dataLen, prevLayer, packet, protocol)
		{}
		HttpMessage() : TextBasedProtocolMessage()
		{}
		HttpMessage(const HttpMessage& other) : TextBasedProtocolMessage(other)
		{}
		HttpMessage& operator=(const HttpMessage& other)
		{
			TextBasedProtocolMessage::operator=(other);
			return *this;
		}

		// implementation of abstract methods
		char getHeaderFieldNameValueSeparator() const
		{
			return ':';
		}
		bool spacesAllowedBetweenHeaderFieldNameAndValue() const
		{
			return true;
		}
	};

	// -------- Class HttpRequestLayer -----------------

	/**
	 * @class HttpRequestLayer
	 * Represents an HTTP request header and inherits all basic functionality of HttpMessage and
	 * TextBasedProtocolMessage. The functionality that is added for this class is the HTTP first line concept. An HTTP
	 * request has the following first line: <i>GET /bla/blabla.asp HTTP/1.1</i> Since it's not an "ordinary" HTTP
	 * field, it requires a special treatment and gets a class of it's own: HttpRequestFirstLine. Unlike most L2-4
	 * protocols, an HTTP request header can spread over more than 1 packet. VanHooks currently doesn't support a
	 * header that is spread over more than 1 packet so in such cases: 1) only the first packet will be parsed as
	 * HttpRequestLayer (the other packets won't be recognized as HttpRequestLayer) and 2) the HTTP header for the first
	 * packet won't be complete (as it continues in the following packets), this why VanHooks can indicate that HTTP
	 * request header is complete or not(doesn't end with "\r\n\r\n" or "\n\n") using HttpMessage#isHeaderComplete()
	 */
	class HttpRequestLayer : public HttpMessage
	{
		friend class HttpRequestFirstLine;

	public:
		/**
		 * HTTP request methods
		 */
		enum HttpMethod
		{
			/** GET */
			HttpGET,
			/** HEAD */
			HttpHEAD,
			/** POST */
			HttpPOST,
			/** PUT */
			HttpPUT,
			/** DELETE */
			HttpDELETE,
			/** TRACE */
			HttpTRACE,
			/** OPTIONS */
			HttpOPTIONS,
			/** CONNECT */
			HttpCONNECT,
			/** PATCH */
			HttpPATCH,
			/** Unknown HTTP method */
			HttpMethodUnknown
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		HttpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new HTTP request header with only the first line filled. Object will be
		 * created without further fields. The user can then add fields using addField() methods
		 * @param[in] method The HTTP method used in this HTTP request
		 * @param[in] uri The URI of the first line
		 * @param[in] version HTTP version to be used in this request
		 */
		HttpRequestLayer(HttpMethod method, const std::string& uri, HttpVersion version);

		virtual ~HttpRequestLayer();

		/**
		 * A copy constructor for this layer. This copy constructor inherits base copy constructor
		 * HttpMessage#HttpMessage() and add the functionality of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		HttpRequestLayer(const HttpRequestLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator
		 * HttpMessage#operator=() and add the functionality of copying the first line as well
		 * @param[in] other The instance to copy from
		 * @return A reference to the assignee
		 */
		HttpRequestLayer& operator=(const HttpRequestLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		HttpRequestFirstLine* getFirstLine() const
		{
			return m_FirstLine;
		}

		/**
		 * The URL is hostname+uri. So given the following URL, for example: "www.cnn.com/main.html", the hostname is
		 * "www.cnn.com" and the URI is "/.main.html". URI and hostname are split to 2 different places inside the HTTP
		 * request packet: URI is in the first line and hostname is in "HOST" field. This methods concatenates the
		 * hostname and URI to the full URL
		 * @return The URL of the HTTP request message
		 */
		std::string getUrl() const;

		// implement Layer's abstract methods
		std::string toString() const;

	private:
		HttpRequestFirstLine* m_FirstLine;
	};

	// -------- Class HttpResponseStatusCode -----------------

	/**
	 * @struct HttpResponseStatusCode
	 * @brief The enum wrapper class of HTTP response status codes
	 */
	class HttpResponseStatusCode
	{
	public:
		/**
		 * @brief Define enum types and the corresponding int values
		 */
		enum Value : int
		{
			/** 100 Continue*/
			Http100Continue = 100,
			/** 101 Switching Protocols*/
			Http101SwitchingProtocols = 101,
			/** 102 Processing */
			Http102Processing = 102,
			/** 103 Early Hints */
			Http103EarlyHints = 103,
			/** 104-199 Unassigned */

			/** 200 OK */
			Http200OK = 200,
			/** 201 Created */
			Http201Created = 201,
			/** 202 Accepted */
			Http202Accepted = 202,
			/** 203 Non-Authoritative Information */
			Http203NonAuthoritativeInformation = 203,
			/** 204 No Content*/
			Http204NoContent = 204,
			/** 205 Reset Content*/
			Http205ResetContent = 205,
			/** 206 Partial Content */
			Http206PartialContent = 206,
			/** 207 Multi-Status */
			Http207MultiStatus = 207,
			/** 208 Already Reported */
			Http208AlreadyReported = 208,
			/** 209-225 Unassigned */
			/** 226 IM Used */
			Http226IMUsed = 226,
			/** 227-299 Unassigned */

			/** 300 Multiple Choices */
			Http300MultipleChoices = 300,
			/** 301 Moved Permanently */
			Http301MovedPermanently = 301,
			/** 302 (various messages) */
			Http302 = 302,
			/** 303 See Other */
			Http303SeeOther = 303,
			/** 304 Not Modified */
			Http304NotModified = 304,
			/** 305 Use Proxy */
			Http305UseProxy = 305,
			/** 306 Switch Proxy */
			Http306SwitchProxy = 306,
			/** 307 Temporary Redirect */
			Http307TemporaryRedirect = 307,
			/** 308 Permanent Redirect, */
			Http308PermanentRedirect = 308,
			/** 309-399 Unassigned */

			/** 400 Bad Request */
			Http400BadRequest = 400,
			/** 401 Unauthorized */
			Http401Unauthorized = 401,
			/** 402 Payment Required */
			Http402PaymentRequired = 402,
			/** 403 Forbidden */
			Http403Forbidden = 403,
			/** 404 Not Found */
			Http404NotFound = 404,
			/** 405 Method Not Allowed */
			Http405MethodNotAllowed = 405,
			/** 406 Not Acceptable */
			Http406NotAcceptable = 406,
			/** 407 Proxy Authentication Required */
			Http407ProxyAuthenticationRequired = 407,
			/** 408 Request Timeout */
			Http408RequestTimeout = 408,
			/** 409 Conflict */
			Http409Conflict = 409,
			/** 410 Gone */
			Http410Gone = 410,
			/** 411 Length Required */
			Http411LengthRequired = 411,
			/** 412 Precondition Failed */
			Http412PreconditionFailed = 412,
			/** 413 RequestEntity Too Large */
			Http413RequestEntityTooLarge = 413,
			/** 414 Request-URI Too Long */
			Http414RequestURITooLong = 414,
			/** 415 Unsupported Media Type */
			Http415UnsupportedMediaType = 415,
			/** 416 Requested Range Not Satisfiable */
			Http416RequestedRangeNotSatisfiable = 416,
			/** 417 Expectation Failed */
			Http417ExpectationFailed = 417,
			/** 418 I'm a teapot */
			Http418ImATeapot = 418,
			/** 419 Authentication Timeout */
			Http419AuthenticationTimeout = 419,
			/** 420 (various messages) */
			Http420 = 420,
			/** 421 Misdirected Request */
			Http421MisdirectedRequest = 421,
			/** 422 Unprocessable Entity */
			Http422UnprocessableEntity = 422,
			/** 423 Locked */
			Http423Locked = 423,
			/** 424 Failed Dependency */
			Http424FailedDependency = 424,
			/** 425 Too Early */
			Http425TooEarly = 425,
			/** 426 Upgrade Required */
			Http426UpgradeRequired = 426,
			/** 427 Unassigned */
			/** 428 Precondition Required */
			Http428PreconditionRequired = 428,
			/** 429 Too Many Requests */
			Http429TooManyRequests = 429,
			/** 430 Unassigned */
			/** 431 Request Header Fields Too Large */
			Http431RequestHeaderFieldsTooLarge = 431,
			/** 432-439 unassigned */
			/** 440 Login Timeout */
			Http440LoginTimeout = 440,
			/** 441-443 unassigned */
			/** 444 No Response */
			Http444NoResponse = 444,
			/** 445-448 unassigned */
			/** 449 Retry With */
			Http449RetryWith = 449,
			/** 450 Blocked by Windows Parental Controls */
			Http450BlockedByWindowsParentalControls = 450,
			/** 451 (various messages) */
			Http451 = 451,
			/** 452-493 unassigned */
			/** 494 Request Header Too Large */
			Http494RequestHeaderTooLarge = 494,
			/** 495 Cert Error */
			Http495CertError = 495,
			/** 496 No Cert */
			Http496NoCert = 496,
			/** 497 HTTP to HTTPS */
			Http497HTTPtoHTTPS = 497,
			/** 498 Token expired/invalid */
			Http498TokenExpiredInvalid = 498,
			/** 499 (various messages) */
			Http499 = 499,

			/** 500 Internal Server Error */
			Http500InternalServerError = 500,
			/** 501 Not Implemented */
			Http501NotImplemented = 501,
			/** 502 Bad Gateway */
			Http502BadGateway = 502,
			/** 503 Service Unavailable */
			Http503ServiceUnavailable = 503,
			/** 504 Gateway Timeout */
			Http504GatewayTimeout = 504,
			/** 505 HTTP Version Not Supported */
			Http505HTTPVersionNotSupported = 505,
			/** 506 Variant Also Negotiates */
			Http506VariantAlsoNegotiates = 506,
			/** 507 Insufficient Storage */
			Http507InsufficientStorage = 507,
			/** 508 Loop Detected */
			Http508LoopDetected = 508,
			/** 509 Bandwidth Limit Exceeded */
			Http509BandwidthLimitExceeded = 509,
			/** 510 Not Extended */
			Http510NotExtended = 510,
			/** 511 Network Authentication Required */
			Http511NetworkAuthenticationRequired = 511,
			/** 512-519 unassigned */
			/** 520 Origin Error */
			Http520OriginError = 520,
			/** 521 Web server is down */
			Http521WebServerIsDown = 521,
			/** 522 Connection timed out */
			Http522ConnectionTimedOut = 522,
			/** 523 Proxy Declined Request */
			Http523ProxyDeclinedRequest = 523,
			/** 524 A timeout occurred */
			Http524aTimeoutOccurred = 524,
			/** 525-597 unassigned */
			/** 598 Network read timeout error */
			Http598NetworkReadTimeoutError = 598,
			/** 599 Network connect timeout error */
			Http599NetworkConnectTimeoutError = 599,

			// clang-format off
			/** Unknown status code */
			HttpStatus1xxCodeUnknown = 900001, // 1xx: Informational - Request received, continuing process
			HttpStatus2xxCodeUnknown = 900002, // 2xx: Success - The action was successfully received, understood, and accepted
			HttpStatus3xxCodeUnknown = 900003, // 3xx: Redirection - Further action must be taken in order to complete the request
			HttpStatus4xxCodeUnknown = 900004, // 4xx: Client Error - The request contains bad syntax or cannot be fulfilled
			HttpStatus5xxCodeUnknown = 900005, // 5xx: Server Error - The server failed to fulfill an apparently valid request
			HttpStatusCodeUnknown = 999999,    // other arbitrary number
			// clang-format on
		};

		HttpResponseStatusCode() = default;

		// cppcheck-suppress noExplicitConstructor
		/**
		 * @brief Construct HttpResponseStatusCode from Value enum
		 * @param[in] statusCode the status code enum
		 */
		HttpResponseStatusCode(Value statusCode) : m_Value(statusCode)
		{}

		/**
		 * @brief Construct HttpResponseStatusCode from the code number and the customized message
		 * @param[in] statusCodeNumber the status code in number, e.g. 200, 404
		 * @param[in] statusMessage the status message, optional, leave empty to use a default message
		 */
		explicit HttpResponseStatusCode(const int& statusCodeNumber, const std::string& statusMessage = "");

		/**
		 * @brief Construct HttpResponseStatusCode from Value enum and the customized message
		 * @param[in] statusCode the status code enum
		 * @param[in] statusMessage the customized status message, optional
		 */
		explicit HttpResponseStatusCode(const Value& statusCode, const std::string& statusMessage);

		// Allow switch and comparisons.
		operator Value() const
		{
			return m_Value;
		}
		// Prevent usage: if(httpResponseStatusCode)
		explicit operator bool() const = delete;

		/**
		 * @brief get status code number as string
		 */
		std::string toString() const
		{
			return std::to_string(m_Value);
		}

		/**
		 * @brief get status code number as int
		 */
		int toInt() const
		{
			return static_cast<int>(m_Value);
		}

		/**
		 * @brief get status code message, e.g. "OK", "Not Found"
		 */
		std::string getMessage() const;
		/**
		 * @return If this HttpResponseStatusCode a valid code
		 * @note Any unknown or error code has an extreme large enum value
		 */
		bool isUnsupportedCode() const
		{
			return m_Value > 599;
		}

	private:
		Value m_Value = HttpStatusCodeUnknown;
		std::string m_CustomizedMessage;
	};

	// -------- Class HttpResponseLayer -----------------

	/**
	 * @class HttpResponseLayer
	 * Represents an HTTP response header and inherits all basic functionality of HttpMessage and
	 * TextBasedProtocolMessage. The functionality that is added for this class is the HTTP first line concept. An HTTP
	 * response has the following first line: <i>200 OK HTTP/1.1</i> Since it's not an "ordinary" HTTP field, it
	 * requires a special treatment and gets a class of it's own: HttpResponseFirstLine. Unlike most L2-4 protocols, an
	 * HTTP response header can spread over more than 1 packet. VanHooks currently doesn't support a header that is
	 * spread over more than 1 packet so in such cases: 1) only the first packet will be parsed as HttpResponseLayer
	 * (the other packets won't be recognized as HttpResponseLayer) and 2) the HTTP header for the first packet won't be
	 * complete (as it continues in the following packets), this why VanHooks can indicate that HTTP response header
	 * is complete or not (doesn't end with "\r\n\r\n" or "\n\n") using HttpMessage#isHeaderComplete()
	 */
	class HttpResponseLayer : public HttpMessage
	{
		friend class HttpResponseFirstLine;

	public:
		// backward compatibility
		using HttpResponseStatusCode = vanhooks::net::HttpResponseStatusCode;

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		HttpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new HTTP response header with only the first line filled. Object will be
		 * created without further fields. The user can then add fields using addField() methods
		 * @param[in] version HTTP version to be used
		 * @param[in] statusCode Status code to be used
		 * @param[in] statusCodeString Most status codes have their default string, e.g 200 is usually "OK", 404 is
		 * usually "Not Found", etc. But the user can set a non-default status code string and it will be written in the
		 * header first line. Empty string ("") means using the default status code string
		 * @deprecated Use other constructors instead.
		 */
		VH_DEPRECATED("Use other constructors instead")
		explicit HttpResponseLayer(HttpVersion version, const HttpResponseStatusCode& statusCode,
		                           const std::string& statusCodeString);

		/**
		 * A constructor that allocates a new HTTP response header with only the first line filled. Object will be
		 * created without further fields. The user can then add fields using addField() methods
		 * @param[in] version HTTP version to be used
		 * @param[in] statusCode Status code to be used
		 */
		explicit HttpResponseLayer(HttpVersion version, const HttpResponseStatusCode& statusCode);

		virtual ~HttpResponseLayer();

		/**
		 * A copy constructor for this layer. This copy constructor inherits base copy constructor
		 * HttpMessage#HttpMessage() and adds the functionality of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		HttpResponseLayer(const HttpResponseLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator
		 * HttpMessage#operator=() and adds the functionality of copying the first line as well
		 * @param[in] other The instance to copy from
		 * @return A reference to the assignee
		 */
		HttpResponseLayer& operator=(const HttpResponseLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		HttpResponseFirstLine* getFirstLine() const
		{
			return m_FirstLine;
		}

		/**
		 * The length of the body of many HTTP response messages is determined by a HTTP header field called
		 * "Content-Length". This method sets The content-length field value. The method supports several cases:
		 *   - If the "Content-Length" field exists - the method will only replace the existing value with the new value
		 *   - If the "Content-Length" field doesn't exist - the method will create this field and put the value in it.
		 * Here are also 2 cases:
		 *   - If prevFieldName is specified - the new "Content-Length" field will be created after it
		 *   - If prevFieldName isn't specified or doesn't exist - the new "Content-Length" field will be created as the
		 * last field before end-of-header field
		 *
		 * @param[in] contentLength The content length value to set
		 * @param[in] prevFieldName Optional field, if specified and "Content-Length" field doesn't exist, it will be
		 * created after it
		 * @return A pointer to the "Content-Length" field, or nullptr if creation failed for some reason
		 */
		HeaderField* setContentLength(int contentLength, const std::string& prevFieldName = "");

		/**
		 * The length of the body of many HTTP response messages is determined by a HTTP header field called
		 * "Content-Length". This method parses this field, extracts its value and return it. If this field doesn't
		 * exist the method will return 0
		 * @return HTTP response body length determined by "Content-Length" field
		 */
		int getContentLength() const;

		// implement Layer's abstract methods

		std::string toString() const;

	private:
		HttpResponseFirstLine* m_FirstLine;
	};

	// -------- Class HttpRequestFirstLine -----------------

	/**
	 * @class HttpRequestFirstLine
	 * Represents an HTTP request header first line. The first line includes 3 parameters: HTTP method (e.g GET, POST,
	 * etc.), URI (e.g /main/index.html) and HTTP version (e.g HTTP/1.1). All these parameters are included in this
	 * class, and the user can retrieve or set them. This class cannot be instantiated by users, it's created inside
	 * HttpRequestLayer and user can get a pointer to an instance of it. All "get" methods of this class will retrieve
	 * the actual data of the HTTP request and the "set" methods will change the packet data. Since HTTP is a textual
	 * protocol, most fields aren't of fixed size and this also applies to the first line parameters. So most "set"
	 * methods of this class need in most cases to shorten or extend the data in HttpRequestLayer. These methods will
	 * return a false value if this action failed
	 */
	class HttpRequestFirstLine
	{
		friend class HttpRequestLayer;

	public:
		/**
		 * @return The HTTP method
		 */
		HttpRequestLayer::HttpMethod getMethod() const
		{
			return m_Method;
		}

		/**
		 * Set the HTTP method
		 * @param[in] newMethod The method to set
		 * @return False if newMethod is HttpRequestLayer#HttpMethodUnknown or if shortening/extending the
		 * HttpRequestLayer data failed. True otherwise
		 */
		bool setMethod(HttpRequestLayer::HttpMethod newMethod);

		/**
		 * @return A copied version of the URI (notice changing the return value won't change the actual data of the
		 * packet)
		 */
		std::string getUri() const;

		/**
		 * Set the URI
		 * @param[in] newUri The URI to set
		 * @return False if shortening/extending the HttpRequestLayer data failed. True otherwise
		 */
		bool setUri(std::string newUri);

		/**
		 * @return The HTTP version
		 */
		HttpVersion getVersion() const
		{
			return m_Version;
		}

		/**
		 * Set the HTTP version. This method doesn't return a value since all supported HTTP versions are of the same
		 * size (HTTP/0.9, HTTP/1.0, HTTP/1.1)
		 * @param[in] newVersion The HTTP version to set
		 */
		void setVersion(HttpVersion newVersion);

		/**
		 * A static method for parsing the HTTP method out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed HTTP method
		 */
		static HttpRequestLayer::HttpMethod parseMethod(const char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the HTTP first line
		 */
		int getSize() const
		{
			return m_FirstLineEndOffset;
		}

		/**
		 * As explained in HttpRequestLayer, an HTTP header can spread over more than 1 packet, so when looking at a
		 * single packet the header can be partial. Same goes for the first line - it can spread over more than 1
		 * packet. This method returns an indication whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		bool isComplete() const
		{
			return m_IsComplete;
		}

		/**
		 * @class HttpRequestFirstLineException
		 * This exception can be thrown while constructing HttpRequestFirstLine (the constructor is private, so the
		 * construction happens only in HttpRequestLayer). This kind of exception will be thrown if trying to construct
		 * with HTTP method of HttpRequestLayer#HttpMethodUnknown or with undefined HTTP version ::HttpVersionUnknown
		 */
		class HttpRequestFirstLineException : public std::exception
		{
		public:
			~HttpRequestFirstLineException() noexcept
			{}
			void setMessage(const std::string& message)
			{
				m_Message = message;
			}
			virtual const char* what() const noexcept
			{
				return m_Message.c_str();
			}

		private:
			std::string m_Message;
		};

	private:
		HttpRequestFirstLine(HttpRequestLayer* httpRequest);
		HttpRequestFirstLine(HttpRequestLayer* httpRequest, HttpRequestLayer::HttpMethod method, HttpVersion version,
		                     const std::string& uri = "/");

		void parseVersion();

		HttpRequestLayer* m_HttpRequest;
		HttpRequestLayer::HttpMethod m_Method;
		HttpVersion m_Version;
		int m_VersionOffset;
		int m_UriOffset;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		HttpRequestFirstLineException m_Exception;
	};

	// -------- Class HttpResponseFirstLine -----------------

	/**
	 * @class HttpResponseFirstLine
	 * Represents an HTTP response header first line. The first line includes 2 parameters: status code (e.g 200 OK, 404
	 * Not Found, etc.), and HTTP version (e.g HTTP/1.1). These 2 parameters are included in this class, and the user
	 * can retrieve or set them. This class cannot be instantiated by users, it's created inside HttpResponseLayer and
	 * user can get a pointer to an instance of it. The "get" methods of this class will retrieve the actual data of the
	 * HTTP response and the "set" methods will change the packet data. Since HTTP is a textual protocol, most fields
	 * aren't of fixed size and this also applies to the first line parameters. So most "set" methods of this class need
	 * in most cases to shorten or extend the data in HttpResponseLayer. These methods will return a false value if this
	 * action failed
	 */
	class HttpResponseFirstLine
	{
		friend class HttpResponseLayer;

	public:
		/**
		 * @return The status code as HttpResponseStatusCode enum
		 */
		HttpResponseStatusCode getStatusCode() const
		{
			return m_StatusCode;
		}

		/**
		 * @return The status code number as integer (e.g 200, 404, etc.)
		 */
		int getStatusCodeAsInt() const;

		/**
		 * @return The status code message (e.g "OK", "Not Found", etc.)
		 */
		std::string getStatusCodeString() const;

		/**
		 * Set the status code
		 * @param[in] newStatusCode The new status code to set
		 * @param[in] statusCodeString An optional parameter: set a non-default status code message (e.g "Bla Bla"
		 * instead of "Not Found"). If this parameter isn't supplied or supplied as empty string (""), the default
		 * message for the status code will be set
		 * @return True if setting the status code was completed successfully, false otherwise
		 * @deprecated Use the other overload instead.
		 */
		VH_DEPRECATED("Use the other overload instead")
		bool setStatusCode(const HttpResponseStatusCode& newStatusCode, const std::string& statusCodeString);

		/**
		 * Set the status code
		 * @param[in] newStatusCode The new status code to set
		 * @return True if setting the status code was completed successfully, false otherwise
		 */
		bool setStatusCode(const HttpResponseStatusCode& newStatusCode);

		/**
		 * @return The HTTP version
		 */
		HttpVersion getVersion() const
		{
			return m_Version;
		}

		/**
		 * Set the HTTP version. This method doesn't return a value since all supported HTTP versions are of the same
		 * size (HTTP/0.9, HTTP/1.0, HTTP/1.1)
		 * @param[in] newVersion The HTTP version to set
		 */
		void setVersion(HttpVersion newVersion);

		/**
		 * A static method for parsing the HTTP status code out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed HTTP status code as enum
		 */
		static HttpResponseStatusCode parseStatusCode(const char* data, size_t dataLen);

		/**
		 * A static method for parsing the HTTP version out of raw first line data (e.g "HTTP/x.y")
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed HTTP status code as enum
		 */
		static HttpVersion parseVersion(const char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the HTTP first line
		 */
		int getSize() const
		{
			return m_FirstLineEndOffset;
		}

		/**
		 * As explained in HttpResponseLayer, an HTTP header can spread over more than 1 packet, so when looking at a
		 * single packet the header can be partial. Same goes for the first line - it can spread over more than 1
		 * packet. This method returns an indication whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		bool isComplete() const
		{
			return m_IsComplete;
		}

		/**
		 * @class HttpResponseFirstLineException
		 * This exception can be thrown while constructing HttpResponseFirstLine (the constructor is private, so the
		 * construction happens only in HttpResponseLayer). This kind of exception will be thrown if trying to construct
		 * with a HTTP status code that is not in HttpResponseStatusCode or with undefined HTTP version
		 * ::HttpVersionUnknown
		 */
		class HttpResponseFirstLineException : public std::exception
		{
		public:
			~HttpResponseFirstLineException() noexcept
			{}
			void setMessage(const std::string& message)
			{
				m_Message = message;
			}
			virtual const char* what() const noexcept
			{
				return m_Message.c_str();
			}

		private:
			std::string m_Message;
		};

	private:
		HttpResponseFirstLine(HttpResponseLayer* httpResponse);
		HttpResponseFirstLine(HttpResponseLayer* httpResponse, HttpVersion version,
		                      const HttpResponseStatusCode& statusCode);

		HttpResponseLayer* m_HttpResponse;
		HttpVersion m_Version;
		HttpResponseStatusCode m_StatusCode;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		HttpResponseFirstLineException m_Exception;
	};

}  // namespace vanhooks::net
// ---- end HttpLayer.h ----

// ---- begin SipLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
// some popular SIP header fields

/** From field */
#define VH_SIP_FROM_FIELD "From"
/** To field */
#define VH_SIP_TO_FIELD "To"
/** Via field */
#define VH_SIP_VIA_FIELD "Via"
/** Call-ID field */
#define VH_SIP_CALL_ID_FIELD "Call-ID"
/** Content-Type field */
#define VH_SIP_CONTENT_TYPE_FIELD "Content-Type"
/** Content-Length field */
#define VH_SIP_CONTENT_LENGTH_FIELD "Content-Length"
/** Content-Disposition field */
#define VH_SIP_CONTENT_DISPOSITION_FIELD "Content-Disposition"
/** Content-Encoding field */
#define VH_SIP_CONTENT_ENCODING_FIELD "Content-Encoding"
/** Content-Language field */
#define VH_SIP_CONTENT_LANGUAGE_FIELD "Content-Language"
/** CSeq field */
#define VH_SIP_CSEQ_FIELD "CSeq"
/** Contact field */
#define VH_SIP_CONTACT_FIELD "Contact"
/** Max-Forwards field */
#define VH_SIP_MAX_FORWARDS_FIELD "Max-Forwards"
/** User-Agent field */
#define VH_SIP_USER_AGENT_FIELD "User-Agent"
/** Accept field */
#define VH_SIP_ACCEPT_FIELD "Accept"
/** Accept-Encoding field */
#define VH_SIP_ACCEPT_ENCODING_FIELD "Accept-Encoding"
/** Accept-Language field */
#define VH_SIP_ACCEPT_LANGUAGE_FIELD "Accept-Language"
/** Allow field */
#define VH_SIP_ALLOW_FIELD "Allow"
/** Authorization field */
#define VH_SIP_AUTHORIZATION_FIELD "Authorization"
/** Date field */
#define VH_SIP_DATE_FIELD "Date"
/** MIME-Version field */
#define VH_SIP_MIME_VERSION_FIELD "MIME-Version"
/** Reason field */
#define VH_SIP_REASON_FIELD "Reason"
/** Supported field */
#define VH_SIP_SUPPORTED_FIELD "Supported"
/** Server field */
#define VH_SIP_SERVER_FIELD "Server"
/** WWW-Authenticate fild */
#define VH_SIP_WWW_AUTHENTICATE_FIELD "WWW-Authenticate"
/** Retry-After field */
#define VH_SIP_RETRY_AFTER_FIELD "Retry-After"
/** Record-Route field */
#define VH_SIP_RECORD_ROUTE_FIELD "Record-Route"

	/**
	 * @class SipLayer
	 * Represents a general SIP message. It's an abstract class and cannot be instantiated. It's inherited by
	 * SipRequestLayer and SipResponseLayer
	 */
	class SipLayer : public TextBasedProtocolMessage
	{
	public:
		/**
		 * The length of the body of many SIP response messages is determined by a SIP header field called
		 * "Content-Length". This method parses this field, extracts its value and return it. If this field doesn't
		 * exist 0 is returned
		 * @return SIP response body length determined by "Content-Length" field
		 */
		int getContentLength() const;

		/**
		 * The length of the body of many SIP messages is determined by a header field called "Content-Length". This
		 * method sets The content-length field value. The method supports several cases:
		 * - If the "Content-Length" field exists - the method will only replace the existing value with the new value
		 * - If the "Content-Length" field doesn't exist - the method will create this field and put the value in it.
		 * Here are also 2 cases:
		 *   - If prevFieldName is specified - the new "Content-Length" field will be created after it
		 *   - If prevFieldName isn't specified or doesn't exist - the new "Content-Length" field will be created as the
		 * last field before end-of-header field
		 *
		 * @param[in] contentLength The content length value to set
		 * @param[in] prevFieldName Optional parameter, if specified and "Content-Length" field doesn't exist, it will
		 * be created after this field
		 * @return A pointer to the "Content-Length" field, or nullptr if creation failed
		 */
		HeaderField* setContentLength(int contentLength, const std::string& prevFieldName = "");

		// Overridden methods

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelSesionLayer;
		}

		/**
		 * Currently identifies only SDP if content-length field exists and set to a value greater than zero.
		 * If content-length field doesn't exist or set to zero and still there is data after this layer, a PayloadLayer
		 * will be created
		 */
		void parseNextLayer();

		/**
		 * Set the content-length only if a content-length field already exists and if its current value is different
		 * than the total length of the next layer(s)
		 */
		void computeCalculateFields();

		/**
		 * A static method that checks whether the port is considered as SIP
		 * @param[in] port The port number to be checked
		 */
		static bool isSipPort(uint16_t port)
		{
			return port == 5060 || port == 5061;
		}

	protected:
		SipLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, ProtocolType protocol)
		    : TextBasedProtocolMessage(data, dataLen, prevLayer, packet, protocol)
		{}
		SipLayer() : TextBasedProtocolMessage()
		{}
		SipLayer(const SipLayer& other) : TextBasedProtocolMessage(other)
		{}
		SipLayer& operator=(const SipLayer& other)
		{
			TextBasedProtocolMessage::operator=(other);
			return *this;
		}

		// implementation of abstract methods
		char getHeaderFieldNameValueSeparator() const
		{
			return ':';
		}
		bool spacesAllowedBetweenHeaderFieldNameAndValue() const
		{
			return true;
		}
	};

	class SipRequestFirstLine;

	/**
	 * @class SipRequestLayer
	 * Represents a SIP request header and inherits all basic functionality of SipLayer and TextBasedProtocolMessage.
	 * The functionality that is added for this class is the SIP first line concept. A SIP request has the following
	 * first line: <i>INVITE sip:bla@bla.com:12345 SIP/2.0</i> Since it's not an "ordinary" header field, it requires a
	 * special treatment and gets a class of it's own: SipRequestFirstLine. In most cases a SIP request will be
	 * contained in a single packet but for cases it is not, only the first packet will be identified as SIP request
	 * layer. You can find out whether the header is complete by using SipLayer#isHeaderComplete()
	 */
	class SipRequestLayer : public SipLayer
	{
		friend class SipRequestFirstLine;

	public:
		/**
		 * SIP request methods
		 */
		enum SipMethod
		{
			/** INVITE */
			SipINVITE,
			/** ACK */
			SipACK,
			/** BYE */
			SipBYE,
			/** CANCEL */
			SipCANCEL,
			/** REFISTER */
			SipREGISTER,
			/** PRACK */
			SipPRACK,
			/** OPTIONS */
			SipOPTIONS,
			/** SUBSCRIBE */
			SipSUBSCRIBE,
			/** NOTIFY */
			SipNOTIFY,
			/** PUBLISH */
			SipPUBLISH,
			/** INFO */
			SipINFO,
			/** REFER */
			SipREFER,
			/** MESSAGE */
			SipMESSAGE,
			/** UPDATE */
			SipUPDATE,
			/** Unknown SIP method */
			SipMethodUnknown
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SipRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new SIP request with only the first line filled. The request will be created
		 * without further fields. The user can then add fields using addField() or insertField() methods
		 * @param[in] method The SIP method to be used in this SIP request
		 * @param[in] requestUri The URI of the request
		 * @param[in] version SIP version to be used in this request. Default is "SIP/2.0"
		 */
		SipRequestLayer(SipMethod method, const std::string& requestUri, const std::string& version = "SIP/2.0");

		~SipRequestLayer();

		/**
		 * A copy constructor for this layer. Inherits base copy constructor SipLayer and adds the functionality
		 * of copying the first line
		 * @param[in] other The instance to copy from
		 */
		SipRequestLayer(const SipRequestLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator
		 * SipLayer#operator=() and adds the functionality of copying the first line
		 * @param[in] other The instance to copy from
		 */
		SipRequestLayer& operator=(const SipRequestLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		SipRequestFirstLine* getFirstLine() const
		{
			return m_FirstLine;
		}

		// implement Layer's abstract methods

		std::string toString() const;

	private:
		SipRequestFirstLine* m_FirstLine;
	};

	class SipResponseFirstLine;

	/**
	 * @class SipResponseLayer
	 * Represents an SIP response message and inherits all basic functionality of SipLayer and TextBasedProtocolMessage.
	 * The functionality that is added for this class is the SIP first line concept. A SIP response has the following
	 * first line: <i>200 OK SIP/2.0</i> Since it's not an "ordinary" header field, it requires a special treatment and
	 * gets a class of it's own: SipResponseFirstLine. In most cases a SIP response will be contained in a single packet
	 * but for cases it is not, only the first packet will be identified as SIP response layer. You can find out whether
	 * the header is complete by using SipLayer#isHeaderComplete()
	 */
	class SipResponseLayer : public SipLayer
	{
		friend class SipResponseFirstLine;

	public:
		/**
		 * Enum for SIP response status codes. List is taken from Wikipedia:
		 * https://en.wikipedia.org/wiki/List_of_SIP_response_codes
		 */
		enum SipResponseStatusCode
		{
			/** Extended search being performed may take a significant time so a forking proxy must send a 100 Trying
			 * response */
			Sip100Trying,
			/** Destination user agent received INVITE, and is alerting user of call */
			Sip180Ringing,
			/** Servers can optionally send this response to indicate a call is being forwarded */
			Sip181CallisBeingForwarded,
			/** Indicates that the destination was temporarily unavailable, so the server has queued the call until the
			 * destination is available. A server may send multiple 182 responses to update progress of the queue */
			Sip182Queued,
			/** This response may be used to send extra information for a call which is still being set up */
			Sip183SessioninProgress,
			/** Can be used by User Agent Server to indicate to upstream SIP entities (including the User Agent Client
			 * (UAC)) that an early dialog has been terminated */
			Sip199EarlyDialogTerminated,
			/** Indicates the request was successful */
			Sip200OK,
			/** Indicates that the request has been accepted for processing, but the processing has not been completed
			 */
			Sip202Accepted,
			/** Indicates the request was successful, but the corresponding response will not be received */
			Sip204NoNotification,
			/** The address resolved to one of several options for the user or client to choose between, which are
			 * listed in the message body or the message's Contact fields */
			Sip300MultipleChoices,
			/** The original Request-URI is no longer valid, the new address is given in the Contact header field, and
			 * the client should update any records of the original Request-URI with the new value */
			Sip301MovedPermanently,
			/** The client should try at the address in the Contact field. If an Expires field is present, the client
			 * may cache the result for that period of time */
			Sip302MovedTemporarily,
			/** The Contact field details a proxy that must be used to access the requested destination */
			Sip305UseProxy,
			/** The call failed, but alternatives are detailed in the message body */
			Sip380AlternativeService,
			/** The request could not be understood due to malformed syntax */
			Sip400BadRequest,
			/** The request requires user authentication. This response is issued by UASs and registrars */
			Sip401Unauthorized,
			/** Reserved for future use */
			Sip402PaymentRequired,
			/** The server understood the request, but is refusing to fulfill it */
			Sip403Forbidden,
			/** The server has definitive information that the user does not exist at the domain specified in the
			 * Request-URI. This status is also returned if the domain in the Request-URI does not match any of the
			 * domains handled by the recipient of the request */
			Sip404NotFound,
			/** The method specified in the Request-Line is understood, but not allowed for the address identified by
			 * the Request-URI */
			Sip405MethodNotAllowed,
			/** The resource identified by the request is only capable of generating response entities that have content
			 * characteristics but not acceptable according to the Accept header field sent in the request */
			Sip406NotAcceptable,
			/** The request requires user authentication. This response is issued by proxies */
			Sip407ProxyAuthenticationRequired,
			/** Couldn't find the user in time. The server could not produce a response within a suitable amount of
			 * time, for example, if it could not determine the location of the user in time. The client MAY repeat the
			 * request without modifications at any later time */
			Sip408RequestTimeout,
			/** User already registered */
			Sip409Conflict,
			/** The user existed once, but is not available here any more */
			Sip410Gone,
			/** The server will not accept the request without a valid Content-Length */
			Sip411LengthRequired,
			/** The given precondition has not been met */
			Sip412ConditionalRequestFailed,
			/** Request body too large */
			Sip413RequestEntityTooLarge,
			/** The server is refusing to service the request because the Request-URI is longer than the server is
			 * willing to interpret */
			Sip414RequestURITooLong,
			/** Request body in a format not supported */
			Sip415UnsupportedMediaType,
			/** Request-URI is unknown to the server */
			Sip416UnsupportedURIScheme,
			/** There was a resource-priority option tag, but no Resource-Priority header */
			Sip417UnknownResourcePriority,
			/** Bad SIP Protocol Extension used, not understood by the server */
			Sip420BadExtension,
			/** The server needs a specific extension not listed in the Supported header */
			Sip421ExtensionRequired,
			/** The received request contains a Session-Expires header field with a duration below the minimum timer */
			Sip422SessionIntervalTooSmall,
			/** Expiration time of the resource is too short */
			Sip423IntervalTooBrief,
			/** The request's location content was malformed or otherwise unsatisfactory */
			Sip424BadLocationInformation,
			/** The server rejected a non-interactive emergency call, indicating that the request was malformed enough
			 * that no reasonable emergency response to the alert can be determined */
			Sip425BadAlertMessage,
			/** The server policy requires an Identity header, and one has not been provided */
			Sip428UseIdentityHeader,
			/** The server did not receive a valid Referred-By token on the request */
			Sip429ProvideReferrerIdentity,
			/** A specific flow to a user agent has failed, although other flows may succeed. This response is intended
			 * for use between proxy devices, and should not be seen by an endpoint (and if it is seen by one, should be
			 * treated as a 400 Bad Request response) */
			Sip430FlowFailed,
			/** The request has been rejected because it was anonymous */
			Sip433AnonymityDisallowed,
			/** The request has an Identity-Info header, and the URI scheme in that header cannot be dereferenced */
			Sip436BadIdentityInfo,
			/** The server was unable to validate a certificate for the domain that signed the request */
			Sip437UnsupportedCertificate,
			/** The server obtained a valid certificate that the request claimed was used to sign the request, but was
			 * unable to verify that signature */
			Sip438InvalidIdentityHeader,
			/** The first outbound proxy the user is attempting to register through does not support the "outbound"
			 * feature of RFC 5626, although the registrar does */
			Sip439FirstHopLacksOutboundSupport,
			/** If a SIP proxy determines a response context has insufficient Incoming Max-Breadth to carry out a
			 * desired parallel fork, and the proxy is unwilling/unable to compensate by forking serially or sending a
			 * redirect, that proxy MUST return a 440 response. A client receiving a 440 response can infer that its
			 * request did not reach all possible destinations */
			Sip440MaxBreadthExceeded,
			/** If a SIP UA receives an INFO request associated with an Info Package that the UA has not indicated
			 * willingness to receive, the UA MUST send a 469 response, which contains a Recv-Info header field with
			 * Info Packages for which the UA is willing to receive INFO requests */
			Sip469BadInfoPackage,
			/** The source of the request did not have the permission of the recipient to make such a request */
			Sip470ConsentNeeded,
			/** Callee currently unavailable */
			Sip480TemporarilyUnavailable,
			/** Server received a request that does not match any dialog or transaction */
			Sip481Call_TransactionDoesNotExist,
			/** Server has detected a loop */
			Sip482LoopDetected,
			/** Max-Forwards header has reached the value '0' */
			Sip483TooManyHops,
			/** Request-URI incomplete */
			Sip484AddressIncomplete,
			/** Request-URI is ambiguous */
			Sip485Ambiguous,
			/** Callee is busy */
			Sip486BusyHere,
			/** Request has terminated by bye or cancel */
			Sip487RequestTerminated,
			/** Some aspect of the session description or the Request-URI is not acceptable */
			Sip488NotAcceptableHere,
			/** The server did not understand an event package specified in an Event header field */
			Sip489BadEvent,
			/** Server has some pending request from the same dialog */
			Sip491RequestPending,
			/** Request contains an encrypted MIME body, which recipient can not decrypt */
			Sip493Undecipherable,
			/** The server has received a request that requires a negotiated security mechanism, and the response
			 * contains a list of suitable security mechanisms for the requester to choose between, or a digest
			 * authentication challenge */
			Sip494SecurityAgreementRequired,
			/** The server could not fulfill the request due to some unexpected condition */
			Sip500ServerInternalError,
			/** The server does not have the ability to fulfill the request, such as because it does not recognize the
			 * request method. (Compare with 405 Method Not Allowed, where the server recognizes the method but does not
			 * allow or support it.) */
			Sip501NotImplemented,
			/** The server is acting as a gateway or proxy, and received an invalid response from a downstream server
			 * while attempting to fulfill the request */
			Sip502BadGateway,
			/** The server is undergoing maintenance or is temporarily overloaded and so cannot process the request. A
			 * "Retry-After" header field may specify when the client may reattempt its request */
			Sip503ServiceUnavailable,
			/** The server attempted to access another server in attempting to process the request, and did not receive
			 * a prompt response */
			Sip504ServerTimeout,
			/** The SIP protocol version in the request is not supported by the server */
			Sip505VersionNotSupported,
			/** The request message length is longer than the server can process */
			Sip513MessageTooLarge,
			/** The server does not support the push notification service identified in a 'pn-provider' SIP URI
			 * parameter */
			Sip555PushNotificationServiceNotSupported,
			/** The server is unable or unwilling to meet some constraints specified in the offer */
			Sip580PreconditionFailure,
			/** All possible destinations are busy. Unlike the 486 response, this response indicates the destination
			 * knows there are no alternative destinations (such as a voicemail server) able to accept the call */
			Sip600BusyEverywhere,
			/** The destination does not wish to participate in the call, or cannot do so, and additionally the
			 * destination knows there are no alternative destinations (such as a voicemail server) willing to accept
			 * the call */
			Sip603Decline,
			/** The server has authoritative information that the requested user does not exist anywhere */
			Sip604DoesNotExistAnywhere,
			/** The user's agent was contacted successfully but some aspects of the session description such as the
			 * requested media, bandwidth, or addressing style were not acceptable */
			Sip606NotAcceptable,
			/** The called party did not want this call from the calling party. Future attempts from the calling party
			 * are likely to be similarly rejected */
			Sip607Unwanted,
			/** An intermediary machine or process rejected the call attempt */
			Sip608Rejected,
			/** Unknown SIP status code */
			SipStatusCodeUnknown
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SipResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that allocates a new SIP response with only the first line filled. The request will be created
		 * without further fields. The user can then add fields using addField() or insertField() methods
		 * @param[in] statusCode SIP status code to set
		 * @param[in] statusCodeString Most status codes have their default string, e.g 200 is usually "OK" etc.
		 * But the user can set a non-default status code string and it will be written in the header first line. Empty
		 * string ("") means using the default status code string. Also, the default is using the default status code
		 * string
		 * @param[in] sipVersion SIP version to set, default is SIP/2.0
		 *
		 */
		explicit SipResponseLayer(SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString = "",
		                          const std::string& sipVersion = "SIP/2.0");

		virtual ~SipResponseLayer();

		/**
		 * A copy constructor for this layer. This copy constructor inherits base copy constructor SipLayer and adds the
		 * functionality of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		SipResponseLayer(const SipResponseLayer& other);

		/**
		 * An assignment operator overload for this layer. This method inherits base assignment operator
		 * SipLayer#operator=() and adds the functionality of copying the first line as well
		 * @param[in] other The instance to copy from
		 */
		SipResponseLayer& operator=(const SipResponseLayer& other);

		/**
		 * @return A pointer to the first line instance for this message
		 */
		SipResponseFirstLine* getFirstLine() const
		{
			return m_FirstLine;
		}

		// implement Layer's abstract methods

		std::string toString() const;

	private:
		SipResponseFirstLine* m_FirstLine;
	};

	/**
	 * @class SipRequestFirstLine
	 * Represents an SIP request first line. The first line includes 3 parameters: SIP method (e.g INVITE, ACK, BYE,
	 * etc.), URI (e.g sip:bla@bla.com:12345) and SIP version (usually SIP/2.0). All these parameters are included in
	 * this class, and the user can retrieve or set them. This class cannot be instantiated by users, it's created
	 * inside SipRequestLayer and user can get a pointer to an instance of it. All "getters" of this class retrieve the
	 * actual data of the SIP request and the "setters" actually change the packet data. Since SIP is a textual
	 * protocol, most fields aren't of fixed size and this also applies to the first line parameters. So many "setter"
	 * methods of this class may need to shorten or extend the data in SipRequestLayer. These methods will return a
	 * false value if this action failed
	 */
	class SipRequestFirstLine
	{
		friend class SipRequestLayer;

	public:
		/**
		 * @return The SIP request method
		 */
		SipRequestLayer::SipMethod getMethod() const
		{
			return m_Method;
		}

		/**
		 * Set the SIP request method
		 * @param[in] newMethod The method to set
		 * @return False if newMethod is SipRequestLayer#SipMethodUnknown or if shortening/extending the SipRequestLayer
		 * data failed. True otherwise
		 */
		bool setMethod(SipRequestLayer::SipMethod newMethod);

		/**
		 * @return A copied version of the URI (notice changing the return value won't change the actual data of the
		 * packet)
		 */
		std::string getUri() const;

		/**
		 * Set the URI
		 * @param[in] newUri The URI to set
		 * @return False if shortening/extending the SipRequestLayer data failed. True otherwise
		 */
		bool setUri(const std::string& newUri);

		/**
		 * @return The SIP version
		 */
		std::string getVersion() const
		{
			return m_Version;
		}

		/**
		 * A static method for parsing the SIP method out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed SIP method
		 */
		static SipRequestLayer::SipMethod parseMethod(const char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the SIP request first line
		 */
		int getSize() const
		{
			return m_FirstLineEndOffset;
		}

		/**
		 * As explained in SipRequestLayer, a SIP message can sometimes spread over more than 1 packet, so when looking
		 * at a single packet the header can be partial. Same goes for the first line - it can spread over more than 1
		 * packet. This method returns an indication whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		bool isComplete() const
		{
			return m_IsComplete;
		}

		/**
		 * @class SipRequestFirstLineException
		 * This exception can be thrown while constructing SipRequestFirstLine (the constructor is private, so the
		 * construction happens only in SipRequestLayer). This kind of exception is thrown if trying to construct with
		 * SIP method of SipRequestLayer#SipMethodUnknown or with empty SIP version
		 */
		class SipRequestFirstLineException : public std::exception
		{
		public:
			~SipRequestFirstLineException() noexcept
			{}
			void setMessage(const std::string& message)
			{
				m_Message = message;
			}
			virtual const char* what() const noexcept
			{
				return m_Message.c_str();
			}

		private:
			std::string m_Message;
		};

	private:
		SipRequestFirstLine(SipRequestLayer* sipRequest);
		SipRequestFirstLine(SipRequestLayer* sipRequest, SipRequestLayer::SipMethod method, const std::string& version,
		                    const std::string& uri);

		void parseVersion();

		SipRequestLayer* m_SipRequest;
		SipRequestLayer::SipMethod m_Method;
		std::string m_Version;
		int m_VersionOffset;
		int m_UriOffset;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		SipRequestFirstLineException m_Exception;
	};

	/**
	 * @class SipResponseFirstLine
	 * Represents an SIP response message first line. The first line includes 2 parameters: status code (e.g 100 Trying
	 * ,200 OK, etc.), and SIP version (usually SIP/2.0). These 2 parameters are included in this class, and the user
	 * can retrieve or set them. This class cannot be instantiated by users, it's created inside SipResponseLayer and
	 * user can get a pointer to an instance of it. The "getter" methods of this class will retrieve the actual data of
	 * the SIP response and the "setter" methods will change the packet data. Since SIP is a textual protocol, most
	 * fields aren't of fixed size and this also applies to the first line parameters. So most "setter" methods of this
	 * class may need to shorten or extend the data in SipResponseLayer. These methods will return a false value if this
	 * action failed
	 */
	class SipResponseFirstLine
	{
		friend class SipResponseLayer;

	public:
		/**
		 * @return The status code as SipResponseLayer#SipResponseStatusCode enum
		 */
		SipResponseLayer::SipResponseStatusCode getStatusCode() const
		{
			return m_StatusCode;
		}

		/**
		 * @return The status code number as integer (e.g 200, 100, etc.)
		 */
		int getStatusCodeAsInt() const;

		/**
		 * @return The status code message (e.g "OK", "Trying", etc.)
		 */
		std::string getStatusCodeString() const;

		/**
		 * Set the status code
		 * @param[in] newStatusCode The new status code to set
		 * @param[in] statusCodeString An optional parameter: set a non-default status code message (e.g "Bla Bla"
		 * instead of "Not Found"). If this parameter isn't supplied or supplied as empty string (""), the default
		 * message for the status code will be set
		 */
		bool setStatusCode(SipResponseLayer::SipResponseStatusCode newStatusCode, std::string statusCodeString = "");

		/**
		 * @return The SIP version
		 */
		std::string getVersion() const
		{
			return m_Version;
		}

		/**
		 * Set the SIP version. The version to set is expected to be in the format of SIP/x.y otherwise an error will be
		 * written to log
		 * @param[in] newVersion The SIP version to set
		 */
		void setVersion(const std::string& newVersion);

		/**
		 * A static method for parsing the SIP status code out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed SIP status code as enum
		 */
		static SipResponseLayer::SipResponseStatusCode parseStatusCode(const char* data, size_t dataLen);

		/**
		 * A static method for parsing the SIP version out of raw data
		 * @param[in] data The raw data
		 * @param[in] dataLen The raw data length
		 * @return The parsed SIP version string or an empty string if version cannot be extracted
		 */
		static std::string parseVersion(const char* data, size_t dataLen);

		/**
		 * @return The size in bytes of the SIP response first line
		 */
		int getSize() const
		{
			return m_FirstLineEndOffset;
		}

		/**
		 * As explained in SipResponseLayer, A SIP message can sometimes spread over more than 1 packet, so when looking
		 * at a single packet the header can be partial. Same goes for the first line - it can spread over more than 1
		 * packet. This method returns an indication whether the first line is partial
		 * @return False if the first line is partial, true if it's complete
		 */
		bool isComplete() const
		{
			return m_IsComplete;
		}

		/**
		 * @class SipResponseFirstLineException
		 * This exception can be thrown while constructing SipResponseFirstLine (the constructor is private, so the
		 * construction happens only in SipResponseLayer). This kind of exception will be thrown if trying to construct
		 * with SIP status code of SipResponseLayer#SipStatusCodeUnknown or with an empty SIP version
		 */
		class SipResponseFirstLineException : public std::exception
		{
		public:
			~SipResponseFirstLineException() noexcept
			{}
			void setMessage(const std::string& message)
			{
				m_Message = message;
			}
			virtual const char* what() const noexcept
			{
				return m_Message.c_str();
			}

		private:
			std::string m_Message;
		};

	private:
		SipResponseFirstLine(SipResponseLayer* sipResponse);
		SipResponseFirstLine(SipResponseLayer* sipResponse, const std::string& version,
		                     SipResponseLayer::SipResponseStatusCode statusCode, std::string statusCodeString = "");

		SipResponseLayer* m_SipResponse;
		std::string m_Version;
		SipResponseLayer::SipResponseStatusCode m_StatusCode;
		int m_FirstLineEndOffset;
		bool m_IsComplete;
		SipResponseFirstLineException m_Exception;
	};

}  // namespace vanhooks::net
// ---- end SipLayer.h ----

// ---- begin SdpLayer.h ----
#include <vector>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

/** Protocol version (v) */
#define VH_SDP_PROTOCOL_VERSION_FIELD "v"
/** Originator and session identifier (o) */
#define VH_SDP_ORIGINATOR_FIELD "o"
/** Session name (s) */
#define VH_SDP_SESSION_NAME_FIELD "s"
/** Session title, media title or short information (i) */
#define VH_SDP_INFO_FIELD "i"
/** URI of description (u) */
#define VH_SDP_URI_FIELD "u"
/** Email address with optional name of contacts (e) */
#define VH_SDP_EMAIL_FIELD "e"
/** Phone number with optional name of contacts (p) */
#define VH_SDP_PHONE_FIELD "p"
/** Connection information (c) */
#define VH_SDP_CONNECTION_INFO_FIELD "c"
/** Bandwidth information (b) */
#define VH_SDP_BANDWIDTH_FIELD "b"
/** Time the session is active (t) */
#define VH_SDP_TIME_FIELD "t"
/** Repeat times (r) */
#define VH_SDP_REPEAT_TIMES_FIELD "r"
/** Time zone adjustments (z) */
#define VH_SDP_TIME_ZONE_FIELD "z"
/** Encryption key (k) */
#define VH_SDP_ENCRYPTION_KEY_FIELD "k"
/** Media attribute (a) */
#define VH_SDP_MEDIA_ATTRIBUTE_FIELD "a"
/** Media name and transport address (m) */
#define VH_SDP_MEDIA_NAME_FIELD "m"

	/**
	 * @class SdpLayer
	 * Represents a SDP (Session Description Protocol) message. SDP is a text-based protocol described by a series of
	 * fields, one per line (lines are separated by CRLF). The form of each field is as follows:<BR>
	 * @code
	 * [character]=[value]
	 * @endcode
	 * Each character represents a certain type of field. All field type are represented as macros in SdpLayer.h file
	 * (for example: VH_SDP_ORIGINATOR_FIELD is a macro for the originator field (o=) ).<BR>
	 * For more details about SDP structure please refer to its Wikipedia page:
	 * https://en.wikipedia.org/wiki/Session_Description_Protocol
	 */
	class SdpLayer : public TextBasedProtocolMessage
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SdpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * An empty c'tor which initialize an empty message with no fields
		 */
		SdpLayer();

		/**
		 * A c'tor which initializes a message with the minimum required fields.<BR>
		 * After this c'tor the message will look like this:
		 *
		 * @code
		 * v=0
		 * o=[username] [sessionID] [sessionVersion] IN IP4 [ipAddress]
		 * s=[sessionName]
		 * c=IN IP4 [ipAddress]
		 * t=[startTime] [endTime]
		 * @endcode
		 *
		 * @param[in] username User's login on the originating host
		 * @param[in] sessionID A globally unique identifier for the session
		 * @param[in] sessionVersion A version number for this session description
		 * @param[in] ipAddress The address of the machine from which the session is created
		 * @param[in] sessionName A textual session name
		 * @param[in] startTime The start time of the session
		 * @param[in] stopTime The stop time of the session
		 */
		SdpLayer(const std::string& username, long sessionID, long sessionVersion, IPv4Address ipAddress,
		         const std::string& sessionName, long startTime, long stopTime);

		~SdpLayer()
		{}

		/**
		 * A copy constructor for this layer. Inherits the base copy constructor and doesn't add
		 * anything else
		 * @param[in] other The instance to copy from
		 */
		SdpLayer(const SdpLayer& other) : TextBasedProtocolMessage(other)
		{}

		/**
		 * An assignment operator overload for this layer. Inherits the base assignment operator
		 * and doesn't add anything else
		 * @param[in] other The instance to copy from
		 */
		SdpLayer& operator=(const SdpLayer& other)
		{
			TextBasedProtocolMessage::operator=(other);
			return *this;
		}

		/**
		 * The 'originator' field (o=) contains the IP address of the the machine from which the session is created.
		 * This IP address can be used to track the RTP data relevant for the call. This method extracts this IP address
		 * from the 'originator' field and returns it. A value of IPv4Address#Zero will be returned in the following
		 * cases: (1) if 'originator' field doesn't exist; (2) if it doesn't contain the IP address; (3) if it contains
		 * a non-IPv4 address
		 * @return The IP address of the the machine from which the session is created
		 */
		IPv4Address getOwnerIPv4Address() const;

		/**
		 * The 'media-description' field (m=) contains the transport port to which the media stream is sent. This port
		 * can be used to track the RTP data relevant for the call. This method extracts this port from the
		 * 'media-description' field and returns it. Since a SDP message can contain several 'media-description' fields,
		 * one for each media type (e.g audio, image, etc.), the user is required to provide the media type. A value of
		 * 0 will be returned in the following cases: (1) if 'media-description' field doesn't exist; (2) if provided
		 * media type was not found; (3) if 'media-description' field didn't contain a port
		 * @param[in] mediaType The media type to search in
		 * @return The transport port to which the media stream is sent
		 */
		uint16_t getMediaPort(const std::string& mediaType) const;

		/**
		 * Adds a 'media-description' field (m=) with all necessary data and attribute fields (a=) with data relevant
		 * for this media.<BR> After this method is run the following block of fields will be added at the end of the
		 * message:
		 *
		 * @code
		 * m=[mediaType] [mediaPort] [mediaProtocol] [mediaFormat]
		 * a=[1st media attribute]
		 * a=[2nd media attribute]
		 * ...
		 * @endcode
		 *
		 * @param[in] mediaType The media type, usually "audio", "video", "text" or "image"
		 * @param[in] mediaPort The transport port to which the media stream is sent
		 * @param[in] mediaProtocol The transport protocol, usually "udp", "RTP/AVP" or "RTP/SAVP"
		 * @param[in] mediaFormat A space-separated list of media format description. For example: "8 96"
		 * @param[in] mediaAttributes A vector of media attributes. Each string in this vector will be
		 * translated into a 'media-attribute' field (a=)
		 * @return True if all fields were added properly or false if at least one field was failed to be added
		 */
		bool addMediaDescription(const std::string& mediaType, uint16_t mediaPort, const std::string& mediaProtocol,
		                         const std::string& mediaFormat, const std::vector<std::string>& mediaAttributes);

		// overridden methods

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelSesionLayer;
		}

		std::string toString() const;

	protected:
		// implementation of abstract methods
		char getHeaderFieldNameValueSeparator() const
		{
			return '=';
		}
		bool spacesAllowedBetweenHeaderFieldNameAndValue() const
		{
			return false;
		}
	};
}  // namespace vanhooks::net
// ---- end SdpLayer.h ----

// ---- begin FtpLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * Class for general FTP message
	 */
	class FtpLayer : public SingleCommandTextProtocol
	{
	protected:
		FtpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SingleCommandTextProtocol(data, dataLen, prevLayer, packet, FTP) {};
		FtpLayer(const std::string& command, const std::string& option)
		    : SingleCommandTextProtocol(command, option, FTP) {};

	public:
		/**
		 * A static method that checks whether the port is considered as FTP control
		 * @param[in] port The port number to be checked
		 */
		static bool isFtpPort(uint16_t port)
		{
			return port == 21;
		}

		/**
		 * A static method that checks whether the port is considered as FTP data
		 * @param[in] port The port number to be checked
		 */
		static bool isFtpDataPort(uint16_t port)
		{
			return port == 20;
		}

		// overridden methods

		/// FTP is the always last so does nothing for this layer
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
		 * @return The OSI layer level of FTP (Application Layer).
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}
	};

	/**
	 * Class for representing the request messages of FTP Layer
	 */
	class FtpRequestLayer : public FtpLayer
	{
	public:
		/**
		 * Enum for FTP command codes
		 */
		enum class FtpCommand : int
		{
			/// Unknown command
			UNK,
			/// Abort an active file transfer.
			ABOR = ('A') | ('B' << 8) | ('O' << 16) | ('R' << 24),
			/// Account information.
			ACCT = ('A') | ('C' << 8) | ('C' << 16) | ('T' << 24),
			/// Authentication/Security Data
			ADAT = ('A') | ('D' << 8) | ('A' << 16) | ('T' << 24),
			/// Allocate sufficient disk space to receive a file.
			ALLO = ('A') | ('L' << 8) | ('L' << 16) | ('O' << 24),
			/// Append (with create)
			APPE = ('A') | ('P' << 8) | ('P' << 16) | ('E' << 24),
			/// Authentication/Security Mechanism
			AUTH = ('A') | ('U' << 8) | ('T' << 16) | ('H' << 24),
			/// Get the available space
			AVBL = ('A') | ('V' << 8) | ('B' << 16) | ('L' << 24),
			/// Clear Command Channel
			CCC = ('C') | ('C' << 8) | ('C' << 16),
			/// Change to Parent Directory.
			CDUP = ('C') | ('D' << 8) | ('U' << 16) | ('P' << 24),
			/// Confidentiality Protection Command
			CONF = ('C') | ('O' << 8) | ('N' << 16) | ('F' << 24),
			/// Client / Server Identification
			CSID = ('C') | ('S' << 8) | ('I' << 16) | ('D' << 24),
			/// Change working directory.
			CWD = ('C') | ('W' << 8) | ('D' << 16),
			/// Delete file.
			DELE = ('D') | ('E' << 8) | ('L' << 16) | ('E' << 24),
			/// Get the directory size
			DSIZ = ('D') | ('S' << 8) | ('I' << 16) | ('Z' << 24),
			/// Privacy Protected Channel
			ENC = ('E') | ('N' << 8) | ('C' << 16),
			/// Specifies an extended address and port to which the server should connect.
			EPRT = ('E') | ('P' << 8) | ('R' << 16) | ('T' << 24),
			/// Enter extended passive mode.
			EPSV = ('E') | ('P' << 8) | ('S' << 16) | ('V' << 24),
			/// Get the feature list implemented by the server.
			FEAT = ('F') | ('E' << 8) | ('A' << 16) | ('T' << 24),
			/// Returns usage documentation on a command if specified, else a general help document is returned.
			HELP = ('H') | ('E' << 8) | ('L' << 16) | ('P' << 24),
			/// Identify desired virtual host on server, by name.
			HOST = ('H') | ('O' << 8) | ('S' << 16) | ('T' << 24),
			/// Language Negotiation
			LANG = ('L') | ('A' << 8) | ('N' << 16) | ('G' << 24),
			/// Returns information of a file or directory if specified, else information of the current working
			/// directory is returned.
			LIST = ('L') | ('I' << 8) | ('S' << 16) | ('T' << 24),
			/// Specifies a long address and port to which the server should connect.
			LPRT = ('L') | ('P' << 8) | ('R' << 16) | ('T' << 24),
			/// Enter long passive mode.
			LPSV = ('L') | ('P' << 8) | ('S' << 16) | ('V' << 24),
			/// Return the last-modified time of a specified file.
			MDTM = ('M') | ('D' << 8) | ('T' << 16) | ('M' << 24),
			/// Modify the creation time of a file.
			MFCT = ('M') | ('F' << 8) | ('C' << 16) | ('T' << 24),
			/// Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file).
			MFF = ('M') | ('F' << 8) | ('F' << 16),
			/// Modify the last modification time of a file.
			MFMT = ('M') | ('F' << 8) | ('M' << 16) | ('T' << 24),
			/// Integrity Protected Command
			MIC = ('M') | ('I' << 8) | ('C' << 16),
			/// Make directory.
			MKD = ('M') | ('K' << 8) | ('D' << 16),
			/// Lists the contents of a directory in a standardized machine-readable format.
			MLSD = ('M') | ('L' << 8) | ('S' << 16) | ('D' << 24),
			/// Provides data about exactly the object named on its command line in a standardized machine-readable
			/// format.
			MLST = ('M') | ('L' << 8) | ('S' << 16) | ('T' << 24),
			/// Sets the transfer mode (Stream, Block, or Compressed).
			MODE = ('M') | ('O' << 8) | ('D' << 16) | ('E' << 24),
			/// Returns a list of file names in a specified directory.
			NLST = ('N') | ('L' << 8) | ('S' << 16) | ('T' << 24),
			/// No operation (dummy packet; used mostly on keepalives).
			NOOP = ('N') | ('O' << 8) | ('O' << 16) | ('P' << 24),
			/// Select options for a feature (for example OPTS UTF8 ON).
			OPTS = ('O') | ('P' << 8) | ('T' << 16) | ('S' << 24),
			/// Authentication password.
			PASS = ('P') | ('A' << 8) | ('S' << 16) | ('S' << 24),
			/// Enter passive mode.
			PASV = ('P') | ('A' << 8) | ('S' << 16) | ('V' << 24),
			/// Protection Buffer Size
			PBSZ = ('P') | ('B' << 8) | ('S' << 16) | ('Z' << 24),
			/// Specifies an address and port to which the server should connect.
			PORT = ('P') | ('O' << 8) | ('R' << 16) | ('T' << 24),
			/// Data Channel Protection Level.
			PROT = ('P') | ('R' << 8) | ('O' << 16) | ('T' << 24),
			/// Print working directory. Returns the current directory of the host.
			PWD = ('P') | ('W' << 8) | ('D' << 16),
			/// Disconnect.
			QUIT = ('Q') | ('U' << 8) | ('I' << 16) | ('T' << 24),
			/// Re initializes the connection.
			REIN = ('R') | ('E' << 8) | ('I' << 16) | ('N' << 24),
			/// Restart transfer from the specified point.
			REST = ('R') | ('E' << 8) | ('S' << 16) | ('T' << 24),
			/// Retrieve a copy of the file
			RETR = ('R') | ('E' << 8) | ('T' << 16) | ('R' << 24),
			/// Remove a directory.
			RMD = ('R') | ('M' << 8) | ('D' << 16),
			/// Remove a directory tree
			RMDA = ('R') | ('M' << 8) | ('D' << 16) | ('A' << 24),
			/// Rename from.
			RNFR = ('R') | ('N' << 8) | ('F' << 16) | ('R' << 24),
			/// Rename to.
			RNTO = ('R') | ('N' << 8) | ('T' << 16) | ('O' << 24),
			/// Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP
			/// output for complete list of supported commands.
			SITE = ('S') | ('I' << 8) | ('T' << 16) | ('E' << 24),
			/// Return the size of a file.
			SIZE = ('S') | ('I' << 8) | ('Z' << 16) | ('E' << 24),
			/// Mount file structure.
			SMNT = ('S') | ('M' << 8) | ('N' << 16) | ('T' << 24),
			/// Use single port passive mode (only one TCP port number for both control connections and passive-mode
			/// data connections)
			SPSV = ('S') | ('P' << 8) | ('S' << 16) | ('V' << 24),
			/// Returns information on the server status, including the status of the current connection
			STAT = ('S') | ('T' << 8) | ('A' << 16) | ('T' << 24),
			/// Accept the data and to store the data as a file at the server site
			STOR = ('S') | ('T' << 8) | ('O' << 16) | ('R' << 24),
			/// Store file uniquely.
			STOU = ('S') | ('T' << 8) | ('O' << 16) | ('U' << 24),
			/// Set file transfer structure.
			STRU = ('S') | ('T' << 8) | ('R' << 16) | ('U' << 24),
			/// Return system type.
			SYST = ('S') | ('Y' << 8) | ('S' << 16) | ('T' << 24),
			/// Get a thumbnail of a remote image file
			THMB = ('T') | ('H' << 8) | ('M' << 16) | ('B' << 24),
			/// Sets the transfer mode (ASCII/Binary).
			TYPE = ('T') | ('Y' << 8) | ('P' << 16) | ('E' << 24),
			/// Authentication username.
			USER = ('U') | ('S' << 8) | ('E' << 16) | ('R' << 24),
			/// Change to the parent of the current working directory
			XCUP = ('X') | ('C' << 8) | ('U' << 16) | ('P' << 24),
			/// Make a directory
			XMKD = ('X') | ('M' << 8) | ('K' << 16) | ('D' << 24),
			/// Print the current working directory
			XPWD = ('X') | ('P' << 8) | ('W' << 16) | ('D' << 24),
			///
			XRCP = ('X') | ('R' << 8) | ('C' << 16) | ('P' << 24),
			/// Remove the directory
			XRMD = ('X') | ('R' << 8) | ('M' << 16) | ('D' << 24),
			///
			XRSQ = ('X') | ('R' << 8) | ('S' << 16) | ('Q' << 24),
			/// Send, mail if cannot
			XSEM = ('X') | ('S' << 8) | ('E' << 16) | ('M' << 24),
			/// Send to terminal
			XSEN = ('X') | ('S' << 8) | ('E' << 16) | ('N' << 24)
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		FtpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : FtpLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * A constructor that creates layer with provided input values
		 * @param[in] command FTP command
		 * @param[in] option Argument of the command
		 */
		explicit FtpRequestLayer(const FtpCommand& command, const std::string& option = "")
		    : FtpLayer(getCommandAsString(command), option) {};

		/**
		 * Set the command of request message
		 * @param[in] code Value to set command
		 * @return True if the operation is successful, false otherwise
		 */
		bool setCommand(FtpCommand code);

		/**
		 * Get the command of request message
		 * @return FtpCommand Value of the command
		 */
		FtpCommand getCommand() const;

		/**
		 * Get the command of request message as string
		 * @return std::string Value of the command as string
		 */
		std::string getCommandString() const;

		/**
		 * Set the command argument of request message
		 * @param[in] value Value to set command argument
		 * @return True if the operation is successful, false otherwise
		 */
		bool setCommandOption(const std::string& value);

		/**
		 * Get the command argument of request message
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return std::string Value of command argument
		 */
		std::string getCommandOption(bool removeEscapeCharacters = true) const;

		/**
		 * Convert the command info to readable string
		 * @param[in] code Command code to convert
		 * @return std::string Returns the command info as readable string
		 */
		static std::string getCommandInfo(FtpCommand code);

		/**
		 * Convert the command to readable string
		 * @param[in] code Command code to convert
		 * @return std::string Returns the command as readable string
		 */
		static std::string getCommandAsString(FtpCommand code);

		// overridden methods

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};

	/**
	 * Class for representing the response messages of FTP Layer
	 */
	class FtpResponseLayer : public FtpLayer
	{
	public:
		/**
		 * Enum for FTP response codes
		 */
		enum class FtpStatusCode : int
		{
			/// Unknown status code
			UNKNOWN,
			/// Restart marker reply
			RESTART_MARKER = 110,
			/// Service ready in nnn minutes
			SERVICE_READY_IN_MIN = 120,
			/// Data connection already open; transfer starting
			DATA_ALREADY_OPEN_START_TRANSFER = 125,
			/// File status okay; about to open data connection
			FILE_OK = 150,
			/// Command okay
			COMMAND_OK = 200,
			/// Command not implemented, superfluous at this site
			COMMAND_NOT_IMPLEMENTED_SUPERFLUOUS = 202,
			/// System status, or system help reply
			SYSTEM_STATUS = 211,
			/// Directory status
			DIR_STATUS = 212,
			/// File status
			FILE_STATUS = 213,
			/// Help message
			HELP_MESSAGE = 214,
			/// NAME system type
			NAME_SYSTEM_TYPE = 215,
			/// Service ready for new user
			SERVICE_READY_FOR_USER = 220,
			/// Service closing control connection
			SERVICE_CLOSING_CONTROL = 221,
			/// Data connection open; no transfer in progress
			DATA_OPEN_NO_TRANSFER = 225,
			/// Closing data connection
			CLOSING_DATA = 226,
			/// Entering Passive Mode
			ENTERING_PASSIVE = 227,
			/// Entering Extended Passive Mode
			ENTERING_EXTENDED_PASSIVE = 229,
			/// User logged in, proceed
			USER_LOG_IN_PROCEED = 230,
			/// User logged in, authorized by security data exchange
			USER_LOG_IN_AUTHORIZED = 232,
			/// Security data exchange complete
			SEC_DATA_EXCHANGE_COMPLETE = 234,
			/// Security data exchange completed successfully
			SEC_DATA_EXCHANGE_COMPLETE_SUCCESS = 235,
			/// Requested file action okay, completed
			REQ_FILE_OK_COMPLETE = 250,
			/// PATHNAME created
			PATHNAME_CREATED = 257,
			/// User name okay, need password
			USER_OK_NEED_PASSWORD = 331,
			/// Need account for login
			NEED_ACCOUNT = 332,
			/// Requested security mechanism is ok
			REQ_SEC_MECHANISM_OK = 334,
			/// Security data is acceptable, more is required
			SEC_IS_ACCEPTABLE = 335,
			/// Username okay, need password. Challenge is ...
			USER_OK_NEED_PASS_CHALLENGE = 336,
			/// Requested file action pending further information
			FILE_PENDING_ACTION = 350,
			/// Service not available, closing control connection
			SERVICE_NOT_AVAILABLE = 421,
			/// Can't open data connection
			CANT_OPEN_DATA_CONNECTION = 425,
			/// Connection closed; transfer aborted
			CONNECTION_CLOSED = 426,
			/// Need some unavailable resource to process security
			NEED_UNAVAILABLE_RESOURCE_TO_SEC = 431,
			/// Requested file action not taken
			REQ_FILE_ACTION_NOT_TAKEN = 450,
			/// Requested action aborted: local error in processing
			REQ_ACTION_ABORTED = 451,
			/// Requested action not taken. Insufficient storage space in system
			REQ_ACTION_NOT_TAKEN = 452,
			/// Syntax error, command unrecognized
			SYNTAX_ERROR_COMMAND_UNRECOGNIZED = 500,
			/// Syntax error in parameters or arguments
			SYNTAX_ERROR_PARAMETER_OR_ARGUMENT = 501,
			/// Command not implemented
			COMMAND_NOT_IMPLEMENTED = 502,
			/// Bad sequence of commands
			BAD_SEQUENCE_COMMANDS = 503,
			/// Command not implemented for that parameter
			COMMAND_NOT_IMPLEMENTED_FOR_PARAMETER = 504,
			/// Network protocol not supported
			NETWORK_PROTOCOL_NOT_SUPPORTED = 522,
			/// Not logged in
			NOT_LOGGED_IN = 530,
			/// Need account for storing files
			NEED_ACCOUNT_FOR_STORE_FILE = 532,
			/// Command protection level denied for policy reasons
			COMMAND_PROTECTION_DENIED = 533,
			/// Request denied for policy reasons
			REQUEST_DENIED = 534,
			/// Failed security check (hash, sequence, etc)
			FAILED_SEC_CHECK = 535,
			/// Requested PROT level not supported by mechanism
			REQ_PROT_LEVEL_NOT_SUPPORTED = 536,
			/// Command protection level not supported by security mechanism
			COMMAND_PROTECTION_LEVEL_NOT_SUPPORTED = 537,
			/// Requested action not taken: File unavailable
			FILE_UNAVAILABLE = 550,
			/// Requested action aborted: page type unknown
			PAGE_TYPE_UNKNOWN = 551,
			/// Requested file action aborted: Exceeded storage allocation
			EXCEED_STORAGE_ALLOCATION = 552,
			/// Requested action not taken: File name not allowed
			FILENAME_NOT_ALLOWED = 553,
			/// Integrity protected reply
			INTEGRITY_PROTECTED = 631,
			/// Confidentiality and integrity protected reply
			CONFIDENTIALITY_AND_INTEGRITY_PROTECTED = 632,
			/// Confidentiality protected reply
			CONFIDENTIALITY_PROTECTED = 633
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		FtpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : FtpLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * A constructor that creates layer with provided input values
		 * @param[in] code Status code
		 * @param[in] option Argument of the status code
		 */
		explicit FtpResponseLayer(const FtpStatusCode& code, const std::string& option = "")
		    : FtpLayer(std::to_string(int(code)), option) {};

		/**
		 * Set the status code of response message
		 * @param[in] code Value to set status code
		 * @return True if the operation is successful, false otherwise
		 */
		bool setStatusCode(FtpStatusCode code);

		/**
		 * Get the status code of response message
		 * @return FtpStatusCode Value of the status code
		 */
		FtpStatusCode getStatusCode() const;

		/**
		 * Get the status code of response message as string
		 * @return std::string Value of the status code as string
		 */
		std::string getStatusCodeString() const;

		/**
		 * Set the argument of response message
		 * @param[in] value Value to set argument
		 * @return True if the operation is successful, false otherwise
		 */
		bool setStatusOption(const std::string& value);

		/**
		 * Get the argument of response message
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return std::string Value of argument
		 */
		std::string getStatusOption(bool removeEscapeCharacters = true) const;

		/**
		 * Convert the status code to readable string
		 * @param[in] code Status code to convert
		 * @return std::string Returns the status info as readable string
		 */
		static std::string getStatusCodeAsString(FtpStatusCode code);

		// overridden methods

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};

	/**
	 * Class for representing the data of FTP Layer
	 */
	class FtpDataLayer : public PayloadLayer
	{
	public:
		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		FtpDataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : PayloadLayer(data, dataLen, prevLayer, packet)
		{
			m_Protocol = FTP;
		};

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};
}  // namespace vanhooks::net
// ---- end FtpLayer.h ----

// ---- begin SmtpLayer.h ----
#ifndef PACKETPP_SMTP_LAYER
#define PACKETPP_SMTP_LAYER


/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * Class for general SMTP message
	 */
	class SmtpLayer : public SingleCommandTextProtocol
	{
	protected:
		SmtpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SingleCommandTextProtocol(data, dataLen, prevLayer, packet, SMTP) {};

		SmtpLayer(const std::string& command, const std::string& option)
		    : SingleCommandTextProtocol(command, option, SMTP) {};

	public:
		/**
		 * A static method that checks whether the port is considered as SMTP control
		 * @param[in] port The port number to be checked
		 * @return True if this an SMTP port (25 or 587)
		 */
		static bool isSmtpPort(uint16_t port)
		{
			return port == 25 || port == 587;
		}

		// overridden methods

		/// SMTP is the always last so does nothing for this layer
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
		 * @return The OSI layer level of SMTP (Application Layer).
		 */
		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}
	};

	/**
	 * Class for representing the request messages of SMTP Layer
	 */
	class SmtpRequestLayer : public SmtpLayer
	{
	public:
		/**
		 * Enum for SMTP command codes
		 */
		enum class SmtpCommand : uint64_t
		{
			/// Unknown command
			UNK,
			/// Starting mail body
			DATA = ('D') | ('A' << 8) | ('T' << 16) | ('A' << 24),
			/// Initiate conversation
			EHLO = ('E') | ('H' << 8) | ('L' << 16) | ('O' << 24),
			/// Expand the mailing list
			EXPN = ('E') | ('X' << 8) | ('P' << 16) | ('N' << 24),
			/// Initiate conversation
			HELO = ('H') | ('E' << 8) | ('L' << 16) | ('O' << 24),
			/// Ask information
			HELP = ('H') | ('E' << 8) | ('L' << 16) | ('P' << 24),
			/// Sender indication
			MAIL = ('M') | ('A' << 8) | ('I' << 16) | ('L' << 24),
			/// No operation
			NOOP = ('N') | ('O' << 8) | ('O' << 16) | ('P' << 24),
			/// Close conversation
			QUIT = ('Q') | ('U' << 8) | ('I' << 16) | ('T' << 24),
			/// Receiver indication
			RCPT = ('R') | ('C' << 8) | ('P' << 16) | ('T' << 24),
			/// Abort transaction
			RSET = ('R') | ('S' << 8) | ('E' << 16) | ('T' << 24),
			/// Identify user
			VRFY = ('V') | ('R' << 8) | ('F' << 16) | ('Y' << 24),
			/// Start TLS handshake
			STARTTLS = (('S') | ('T' << 8) | ('A' << 16) | ('R' << 24) |
			            static_cast<uint64_t>(('T') | ('T' << 8) | ('L' << 16) | ('S' << 24)) << 32),
			/// Reverse the role of sender and receiver
			TURN = ('T') | ('U' << 8) | ('R' << 16) | ('N' << 24),
			/// Send mail to terminal
			SEND = ('S') | ('E' << 8) | ('N' << 16) | ('D' << 24),
			/// Send mail to terminal or to mailbox
			SOML = ('S') | ('O' << 8) | ('M' << 16) | ('L' << 24),
			/// Send mail to terminal and mailbox
			SAML = ('S') | ('A' << 8) | ('M' << 16) | ('L' << 24),
			/// Authenticate client and server
			AUTH = ('A') | ('U' << 8) | ('T' << 16) | ('H' << 24),
			/// Reverse the role of sender and receiver
			ATRN = ('A') | ('T' << 8) | ('R' << 16) | ('N' << 24),
			/// Submit mail contents
			BDAT = ('B') | ('D' << 8) | ('A' << 16) | ('T' << 24),
			/// Request to start SMTP queue processing
			ETRN = ('E') | ('T' << 8) | ('R' << 16) | ('N' << 24),
			/// Release status of the channel
			XADR = ('X') | ('A' << 8) | ('D' << 16) | ('R' << 24),
			/// Release status of the circuit checking facility
			XCIR = ('X') | ('C' << 8) | ('I' << 16) | ('R' << 24),
			/// Release status of the number of messages in channel queues
			XSTA = ('X') | ('S' << 8) | ('T' << 16) | ('A' << 24),
			/// Release status of whether a compiled configuration and character set are in use
			XGEN = ('X') | ('G' << 8) | ('E' << 16) | ('N' << 24)
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SmtpRequestLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SmtpLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * A constructor that creates layer with provided input values
		 * @param[in] command SMTP command
		 * @param[in] option Argument of the command
		 */
		explicit SmtpRequestLayer(const SmtpCommand& command, const std::string& option = "")
		    : SmtpLayer(getCommandAsString(command), option) {};

		/**
		 * Set the command of request message
		 * @param[in] code Value to set command
		 * @return True if the operation is successful, false otherwise
		 */
		bool setCommand(SmtpCommand code);

		/**
		 * Get the command of request message
		 * @return Value of the command
		 */
		SmtpCommand getCommand() const;

		/**
		 * Get the command of request message as string
		 * @return Value of the command as string
		 */
		std::string getCommandString() const;

		/**
		 * Set the command argument of request message
		 * @param[in] value Value to set command argument
		 * @return True if the operation is successful, false otherwise
		 */
		bool setCommandOption(const std::string& value);

		/**
		 * Get the command argument of request message
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return Value of command argument
		 */
		std::string getCommandOption(bool removeEscapeCharacters = true) const;

		/**
		 * Convert the command info to readable string
		 * @param[in] code Command code to convert
		 * @return Returns the command info as readable string
		 */
		static std::string getCommandInfo(SmtpCommand code);

		/**
		 * Convert the command to readable string
		 * @param[in] code Command code to convert
		 * @return Returns the command as readable string
		 */
		static std::string getCommandAsString(SmtpCommand code);

		// overridden methods

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};

	/**
	 * Class for representing the response messages of SMTP Layer
	 */
	class SmtpResponseLayer : public SmtpLayer
	{
	public:
		/**
		 * Enum for SMTP response codes
		 */
		enum class SmtpStatusCode : int
		{
			/// System status, or system help reply
			SYSTEM_STATUS = 211,
			/// Help message
			HELP_MESSAGE = 214,
			/// \<domain\> Service ready
			SERVICE_READY = 220,
			/// \<domain\> Service closing transmission channel
			SERVICE_CLOSE = 221,
			/// Authentication successful
			AUTH_SUCCESS = 235,
			/// Requested mail action okay, completed
			COMPLETED = 250,
			/// User not local; will forward to <forward-path>
			WILL_FORWARD = 251,
			/// Cannot VRFY user, but will accept message and attempt delivery
			CANNOT_VERIFY = 252,
			/// AUTH input
			AUTH_INPUT = 334,
			/// Start mail input; end with \<CRLF\>.\<CRLF\>
			MAIL_INPUT = 354,
			/// \<domain\> Service not available, closing transmission channel
			SERVICE_UNAVAILABLE = 421,
			/// A password transition is needed
			PASS_NEEDED = 432,
			/// Requested mail action not taken: mailbox unavailable (mail busy or temporarily blocked)
			MAILBOX_UNAVAILABLE_TEMP = 450,
			/// Requested action aborted: local error in processing
			ABORT_LOCAL_ERROR = 451,
			/// Requested action not taken: insufficient system storage
			INSUFFICIENT_STORAGE = 452,
			/// Temporary authentication failed
			TEMP_AUTH_FAILED = 454,
			/// Server unable to accommodate parameters
			PARAM_NOT_ACCOMMODATED = 455,
			/// Syntax error, command unrecognized
			CMD_NOT_RECOGNIZED = 500,
			/// Syntax error in parameters or arguments
			SYNTAX_ERROR_PARAM = 501,
			/// Command not implemented
			CMD_NOT_IMPLEMENTED = 502,
			/// Bad sequence of commands
			CMD_BAD_SEQUENCE = 503,
			/// Command parameter not implemented
			PARAM_NOT_IMPLEMENTED = 504,
			/// Server does not accept mail
			MAIL_NOT_ACCEPTED = 521,
			/// Encryption needed
			ENCRYPT_NEED = 523,
			/// Authentication required
			AUTH_REQUIRED = 530,
			/// Authentication mechanism is too weak
			AUTH_TOO_WEAK = 534,
			/// Authentication credentials invalid
			AUTH_CRED_INVALID = 535,
			/// Encryption required for requested authentication mechanism
			ENCRYPT_REQUIRED = 538,
			/// Requested action not taken: mailbox unavailable
			MAILBOX_UNAVAILABLE = 550,
			/// User not local; please try <forward-path>
			USER_NOT_LOCAL = 551,
			/// Requested mail action aborted: exceeded storage allocation
			EXCEED_STORAGE = 552,
			/// Requested action not taken: mailbox name not allowed
			NAME_NOT_ALLOWED = 553,
			/// Transaction failed
			TRANSACTION_FAIL = 554,
			/// Domain does not accept mail
			DOMAIN_NOT_ACCEPT = 556
		};

		/** A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SmtpResponseLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SmtpLayer(data, dataLen, prevLayer, packet) {};

		/**
		 * A constructor that creates layer with provided input values
		 * @param[in] code Status code
		 * @param[in] option Argument of the status code
		 */
		explicit SmtpResponseLayer(const SmtpStatusCode& code, const std::string& option = "")
		    : SmtpLayer(std::to_string(int(code)), option) {};

		/**
		 * Set the status code of response message
		 * @param[in] code Value to set status code
		 * @return True if the operation is successful, false otherwise
		 */
		bool setStatusCode(SmtpStatusCode code);

		/**
		 * Get the status code of response message
		 * @return Value of the status code
		 */
		SmtpStatusCode getStatusCode() const;

		/**
		 * Get the status code of response message as string
		 * @return Value of the status code as string
		 */
		std::string getStatusCodeString() const;

		/**
		 * Set the argument of response message
		 * @param[in] value Value to set argument
		 * @return True if the operation is successful, false otherwise
		 */
		bool setStatusOption(const std::string& value);

		/**
		 * Get the argument of response message
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return Value of argument
		 */
		std::string getStatusOption(bool removeEscapeCharacters = true) const;

		/**
		 * Convert the status code to readable string
		 * @param[in] code Status code to convert
		 * @return Returns the status info as readable string
		 */
		static std::string getStatusCodeAsString(SmtpStatusCode code);

		// overridden methods

		/**
		 * @return Returns the protocol info as readable string
		 */
		std::string toString() const;
	};
}  // namespace vanhooks::net

#endif /* PACKETPP_SMTP_LAYER */
// ---- end SmtpLayer.h ----

// ---- begin TelnetLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * Class for representing the Telnet Layer
	 */
	class TelnetLayer : public Layer
	{
	private:
		// Position iterator for next command
		size_t lastPositionOffset;

		// Checks if position is a data field
		bool isDataField(uint8_t* pos) const;
		// Checks if position is a command field
		bool isCommandField(uint8_t* pos) const;
		// Returns distance to next IAC
		size_t distanceToNextIAC(uint8_t* startPos, size_t maxLength);
		// Returns length of provided field
		size_t getFieldLen(uint8_t* startPos, size_t maxLength);
		// Get position of next data field
		uint8_t* getNextDataField(uint8_t* pos, size_t len);
		// Get position of next command field
		uint8_t* getNextCommandField(uint8_t* pos, size_t len);
		// Get options of provided field
		int16_t getSubCommand(uint8_t* pos, size_t len);
		// Get data of provided field
		uint8_t* getCommandData(uint8_t* pos, size_t& slen);

	public:
		/**
		 * Telnet Command Indicator
		 */
		enum class TelnetCommand : int
		{
			/// Indicator to parser reached end of packet
			TelnetCommandEndOfPacket = -1,

			/// End of file
			EndOfFile = 236,
			/// Suspend current process
			Suspend,
			/// Abort Process
			Abort,
			/// End of Record
			EndOfRecordCommand,
			/// Marks the end of a Telnet option subnegotiation, used with the SB code to specify more specific option
			/// parameters.
			SubnegotiationEnd,
			/// Null command; does nothing.
			NoOperation,
			/// Used to mark the end of a sequence of data that the recipient should scan for urgent Telnet commands.
			DataMark,
			/// Represents the pressing of the “break” or “attention” key on the terminal.
			Break,
			/// Tells the recipient to interrupt, abort, suspend or terminate the process currently in use.
			InterruptProcess,
			/// Instructs the remote host to continue running the current process, but discard all remaining output from
			/// it. This may be needed if a program starts to send unexpectedly large amounts of data to the user.
			AbortOutput,
			/// May be used to check that the remote host is still “alive”. When this character is sent the remote host
			/// returns some type of output to indicate that it is still functioning.
			AreYouThere,
			/// Instructs the recipient to delete the last undeleted character from the data stream. Used to “undo” the
			/// sending of a character.
			EraseCharacter,
			/// Tells the recipient to delete all characters from the data stream back to (but not including) the last
			/// end of line (CR+LF) sequence.
			EraseLine,
			/// Used in Telnet half-duplex mode to signal the other device that it may transmit.
			GoAhead,
			/// Marks the beginning of a Telnet option subnegotiation, used when an option requires the client and
			/// server to exchange parameters.
			Subnegotiation,
			/// Indicates that the device sending this code is willing to perform or continue performing a particular
			/// option.
			WillPerform,
			/// Indicates that the device sending this code is either not willing to perform a particular option, or is
			/// now refusing to continue to perform it.
			WontPerform,
			/// Requests that the other device perform a particular option or confirms the expectation that the other
			/// device will perform that option.
			DoPerform,
			/// Specifies that the other party not perform an option, or confirms a device’s expectation that the other
			/// party not perform an option.
			DontPerform,
			/// Precedes command values 240 through 254 as described above. A pair of IAC bytes in a row represents the
			/// data value 255.
			InterpretAsCommand
		};

		/**
		 * Telnet Options
		 */
		enum class TelnetOption : int
		{
			/// Internal return for no option detected
			TelnetOptionNoOption = -1,

			/// Binary Transmission RFC856 https://www.iana.org/go/rfc856
			TransmitBinary = 0,
			/// Echo RFC857 https://www.iana.org/go/rfc857
			Echo,
			/// Reconnection
			Reconnection,
			/// Suppress Go Ahead RFC858 https://www.iana.org/go/rfc858
			SuppressGoAhead,
			/// Negotiate approximate message size
			ApproxMsgSizeNegotiation,
			/// Status RFC859 https://www.iana.org/go/rfc859
			Status,
			/// Timing Mark RFC860 https://www.iana.org/go/rfc860
			TimingMark,
			/// RCTE, Remote Controlled Transmission and Echo RFC726 https://www.iana.org/go/rfc726
			RemoteControlledTransAndEcho,
			/// Output Line Width
			OutputLineWidth,
			/// Output Page Size
			OutputPageSize,
			/// NAOCRD, Negotiate About Output Carriage-Return Disposition RFC652 https://www.iana.org/go/rfc652
			OutputCarriageReturnDisposition,
			/// NAOHTS, Negotiate About Output Horizontal Tabstops RFC653 https://www.iana.org/go/rfc653
			OutputHorizontalTabStops,
			/// NAOHTD, Negotiate About Output Horizontal Tab Disposition RFC654 https://www.iana.org/go/rfc654
			OutputHorizontalTabDisposition,
			/// NAOFFD, Negotiate About Output Formfeed Disposition RFC655 https://www.iana.org/go/rfc655
			OutputFormfeedDisposition,
			/// NAOVTS, Negotiate About Vertical Tabstops RFC656 https://www.iana.org/go/rfc656
			OutputVerticalTabStops,
			/// NAOVTD, Negotiate About Output Vertcial Tab Disposition RFC657 https://www.iana.org/go/rfc657
			OutputVerticalTabDisposition,
			/// NAOLFD, Negotiate About Output Linefeed Disposition RFC658 https://www.iana.org/go/rfc658
			OutputLinefeedDisposition,
			/// Extended ASCII RFC698 https://www.iana.org/go/rfc698
			ExtendedASCII,
			/// Logout RFC727 https://www.iana.org/go/rfc727
			Logout,
			/// BM, Byte Macro RFC735 https://www.iana.org/go/rfc735
			ByteMacro,
			/// Data Entry Terminal RFC1043 - RFC732 https://www.iana.org/go/rfc1043 https://www.iana.org/go/rfc732
			DataEntryTerminal,
			/// SUPDUP RFC736 - RFC734 https://www.iana.org/go/rfc736 https://www.iana.org/go/rfc734
			SUPDUP,
			/// SUPDUP Output RFC749 https://www.iana.org/go/rfc749
			SUPDUPOutput,
			/// Send Location RFC779 https://www.iana.org/go/rfc779
			SendLocation,
			/// Terminal Type RFC1091 https://www.iana.org/go/rfc1091
			TerminalType,
			/// End of record RFC885 https://www.iana.org/go/rfc885
			EndOfRecordOption,
			/// TUID, TACACS User Identification RFC927 https://www.iana.org/go/rfc927
			TACACSUserIdentification,
			/// OUTMRK, Output Marking RFC933 https://www.iana.org/go/rfc933
			OutputMarking,
			/// TTYLOC, Terminal Location Number RFC946 https://www.iana.org/go/rfc946
			TerminalLocationNumber,
			/// Telnet 3270 Regime RFC1041 https://www.iana.org/go/rfc1041
			Telnet3270Regime,
			/// X.3 PAD RFC1053 https://www.iana.org/go/rfc1053
			X3Pad,
			/// NAWS, Negotiate About Window Size RFC1073 https://www.iana.org/go/rfc1073
			NegotiateAboutWindowSize,
			/// Terminal Speed RFC1079 https://www.iana.org/go/rfc1079
			TerminalSpeed,
			/// Remote Flow Control RFC1372 https://www.iana.org/go/rfc1372
			RemoteFlowControl,
			/// Line Mode RFC1184 https://www.iana.org/go/rfc1184
			Linemode,
			/// X Display Location RFC1096 https://www.iana.org/go/rfc1096
			XDisplayLocation,
			/// Environment Option RFC1408 https://www.iana.org/go/rfc1408
			EnvironmentOption,
			/// Authentication Option RFC2941 https://www.iana.org/go/rfc2941
			AuthenticationOption,
			/// Encryption Option RFC2946 https://www.iana.org/go/rfc2946
			EncryptionOption,
			/// New Environment Option RFC1572 https://www.iana.org/go/rfc1572
			NewEnvironmentOption,
			/// TN3270E RFC2355 https://www.iana.org/go/rfc2355
			TN3270E,
			/// X Server Authentication
			XAuth,
			/// Charset RFC2066 https://www.iana.org/go/rfc2066
			Charset,
			/// RSP, Telnet Remote Serial Port
			TelnetRemoteSerialPort,
			/// Com Port Control Option RFC2217 https://www.iana.org/go/rfc2217
			ComPortControlOption,
			/// Telnet Suppress Local Echo
			TelnetSuppressLocalEcho,
			/// Telnet Start TLS
			TelnetStartTLS,
			/// Kermit RFC2840 https://www.iana.org/go/rfc2840
			Kermit,
			/// Send URL
			SendURL,
			/// Forward X Server
			ForwardX,

			/// Telnet Option Pragma Logon
			TelOptPragmaLogon = 138,
			/// Telnet Option SSPI Logon
			TelOptSSPILogon,
			/// Telnet Option Pragma Heartbeat
			TelOptPragmaHeartbeat,

			/// Extended option list
			ExtendedOptions = 255
		};

		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		TelnetLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, Telnet)
		{
			lastPositionOffset = SIZE_MAX;
		};

		/**
		 * Get the Telnet data as readable string
		 * @param[in] removeEscapeCharacters Whether non-alphanumerical characters should be removed or not
		 * @return Full payload as readable string, empty if Telnet packet contains control commands/options.
		 */
		std::string getDataAsString(bool removeEscapeCharacters = true);

		/**
		 * Get the total number of detected Telnet commands
		 * @return size_t The number of Telnet commands
		 */
		size_t getTotalNumberOfCommands();

		/**
		 * Returns the number of occurrences of provided command
		 * @param[in] command Telnet command to count
		 * @return size_t Number of occurrences of command
		 */
		size_t getNumberOfCommands(TelnetCommand command);

		/**
		 * Returns the first command of packet
		 * @return TelnetCommand First detected command value, TelnetCommandEndOfPacket if there is no command field
		 */
		TelnetCommand getFirstCommand();

		/**
		 * Returns the next command of packet. Uses an internal iterator. The iterator resets when reached end of
		 * packet.
		 * @return TelnetCommand Detected command value, TelnetCommandEndOfPacket if reached the end of packet.
		 */
		TelnetCommand getNextCommand();

		/**
		 * Returns the option of current command. Uses an internal iterator. Iterator can be moved with getNextCommand
		 * @return TelnetOption Option of current command
		 */
		TelnetOption getOption();

		/**
		 * Returns the option of provided command. It will return option of first occurrence of the command
		 * @param[in] command Telnet command to search
		 * @return TelnetOption Option of the command. Returns TelnetOptionNoOption if the provided command not found.
		 */
		TelnetOption getOption(TelnetCommand command);

		/**
		 * Returns the data of current command. Uses an internal iterator. Iterator can be moved with getNextCommand
		 * @param[out] length Length of the data of current command
		 * @return uint8_t* Pointer to the data of current command. nullptr if there is no data for this command.
		 */
		uint8_t* getOptionData(size_t& length);

		/**
		 * Returns the data of provided command. It will return data of first occurrence of the command
		 * @param[in] command Telnet command to search
		 * @param[out] length Length of the data of current command
		 * @return uint8_t* Pointer to the data of current command. nullptr if there is no data for this command or if
		 * can't find the command.
		 */
		uint8_t* getOptionData(TelnetCommand command, size_t& length);

		/**
		 * Convert the Telnet Command to readable string
		 * @param[in] val Value of the command
		 * @return The Telnet Command as readable string
		 */
		static std::string getTelnetCommandAsString(TelnetCommand val);

		/**
		 * Convert the Telnet option to readable string
		 * @param[in] val Value of the option
		 * @return The Telnet Option as readable string
		 */
		static std::string getTelnetOptionAsString(TelnetOption val);

		/**
		 * A static method that checks whether the port is considered as Telnet
		 * @param[in] port The port number to be checked
		 */
		static bool isTelnetPort(uint16_t port)
		{
			return port == 23;
		}

		/**
		 * A static method that takes a byte array and detects whether it is a Telnet message
		 * @param[in] data A byte array
		 * @param[in] dataSize The byte array size (in bytes)
		 * @return True if the data is identified as Telnet message
		 */
		static bool isDataValid(const uint8_t* data, size_t dataSize)
		{
			return data && dataSize;
		}

		// overridden methods

		/// Parses the next layer. Telnet is the always last so does nothing for this layer
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
		 * @return The OSI layer level of Telnet (Application Layer).
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
// ---- end TelnetLayer.h ----

