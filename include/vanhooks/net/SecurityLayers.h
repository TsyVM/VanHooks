#pragma once

// ===== Consolidated header: SecurityLayers.h =====
// Merges: SSLCommon, Asn1Codec, SSLHandshake, SSLLayer, LdapLayer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "Common.h"
#include "PacketCore.h"

// ---- begin SSLCommon.h ----
#include <string>
#include <stdint.h>

/**
 * @file
 * See detailed explanation of the TLS/SSL protocol support in VanHooks in SSLLayer.h
 */

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct ssl_tls_record_layer
	 * The common part of all SSL/TLS messages
	 */
#pragma pack(push, 1)
	struct ssl_tls_record_layer
	{
		/** Message (record) type (one of ::SSLRecordType) */
		uint8_t recordType;
		/** Message (record) version (one of SSLVersion::SSLVersionEnum) */
		uint16_t recordVersion;
		/** Message (record) length in bytes */
		uint16_t length;
	};
#pragma pack(pop)

	/**
	 * @struct ssl_tls_handshake_layer
	 * The common part of all SSL/TLS handshake message types
	 */
#pragma pack(push, 1)
	struct ssl_tls_handshake_layer
	{
		/** Type of the handshake message (one of ::SSLHandshakeType) */
		uint8_t handshakeType;
		/** Length of the message. Length is 3-Byte long, This is the MSB byte */
		uint8_t length1;
		/** Length of the message. Length is 3-Byte long, This is the 2 LSB bytes */
		uint16_t length2;
	};
#pragma pack(pop)

	/**
	 * @struct ssl_tls_client_server_hello
	 * The common header part of client-hello and server-hello handshake messages
	 */
#pragma pack(push, 1)
	struct ssl_tls_client_server_hello : ssl_tls_handshake_layer
	{
		/** SSL/TLS handshake version (one of SSLVersion::SSLVersionEnum) */
		uint16_t handshakeVersion;
		/** 32-bytes random number */
		uint8_t random[32];
	};
#pragma pack(pop)

	/**
	 * @struct ssl_tls_change_cipher_spec
	 * SSL/TLS change-cipher-spec message structure
	 */
#pragma pack(push, 1)
	struct ssl_tls_change_cipher_spec
	{
		/** Unused byte */
		uint8_t changeCipherSpec;
	};
#pragma pack(pop)

	/**
	 * @struct ssl_tls_alert
	 * SSL/TLS alert message structure
	 */
#pragma pack(push, 1)
	struct ssl_tls_alert
	{
		/** Alert level (one of ::SSLAlertLevel) */
		uint8_t alertLevel;
		/** Alert description (one of ::SSLAlertDescription) */
		uint8_t alertDescription;
	};
#pragma pack(pop)

	/**
	 * SSL/TLS message types
	 */
	enum SSLRecordType
	{
		/** Change-cipher-spec message */
		SSL_CHANGE_CIPHER_SPEC = 20,
		/** SSL alert message */
		SSL_ALERT = 21,
		/** SSL handshake message */
		SSL_HANDSHAKE = 22,
		/** SSL data message */
		SSL_APPLICATION_DATA = 23
	};

	/**
	 * @class SSLVersion
	 * A wrapper class for SSL/TLS versions. The SSL/TLS version is typically represented by a 2-byte number,
	 * for example TLS 1.2 is represented by 0x0303.
	 * This class wraps the numeric value and provides methods to convert it into an enum, string, etc.
	 */
	class SSLVersion
	{
	public:
		/**
		 * SSL/TLS versions enum
		 */
		enum SSLVersionEnum
		{
			/** SSL 2.0 */
			SSL2 = 0x0200,
			/** SSL 3.0 */
			SSL3 = 0x0300,
			/** TLS 1.0 */
			TLS1_0 = 0x0301,
			/** TLS 1.1 */
			TLS1_1 = 0x0302,
			/** TLS 1.2 */
			TLS1_2 = 0x0303,
			/** TLS 1.3 */
			TLS1_3 = 0x0304,
			/** TLS 1.3 (draft 14) */
			TLS1_3_D14 = 0x7f0e,
			/** TLS 1.3 (draft 15) */
			TLS1_3_D15 = 0x7f0f,
			/** TLS 1.3 (draft 16) */
			TLS1_3_D16 = 0x7f10,
			/** TLS 1.3 (draft 17) */
			TLS1_3_D17 = 0x7f11,
			/** TLS 1.3 (draft 18) */
			TLS1_3_D18 = 0x7f12,
			/** TLS 1.3 (draft 19) */
			TLS1_3_D19 = 0x7f13,
			/** TLS 1.3 (draft 20) */
			TLS1_3_D20 = 0x7f14,
			/** TLS 1.3 (draft 21) */
			TLS1_3_D21 = 0x7f15,
			/** TLS 1.3 (draft 22) */
			TLS1_3_D22 = 0x7f16,
			/** TLS 1.3 (draft 23) */
			TLS1_3_D23 = 0x7f17,
			/** TLS 1.3 (draft 24) */
			TLS1_3_D24 = 0x7f18,
			/** TLS 1.3 (draft 25) */
			TLS1_3_D25 = 0x7f19,
			/** TLS 1.3 (draft 26) */
			TLS1_3_D26 = 0x7f1a,
			/** TLS 1.3 (draft 27) */
			TLS1_3_D27 = 0x7f1b,
			/** TLS 1.3 (draft 28) */
			TLS1_3_D28 = 0x7f1c,
			/** TLS 1.3 (Facebook draft 23) */
			TLS1_3_FBD23 = 0xfb17,
			/** TLS 1.3 (Facebook draft 26) */
			TLS1_3_FBD26 = 0xfb1a,
			/** Unknown value */
			Unknown = 0
		};

		/**
		 * A c'tor for this class.
		 * @param[in] sslVersionValue The numeric value representing this SSL/TLS version. For example:
		 * for TLS 1.2 this would be 0x0303.
		 */
		explicit SSLVersion(uint16_t sslVersionValue)
		{
			m_SSLVersionValue = sslVersionValue;
		}

		/**
		 * @return An enum value of type SSLVersion::SSLVersionEnum representing the SSL/TLS version.
		 * If the numeric value is an invalid SSL/TLS version SSLVersion::Unknown will be returned.
		 * @param[in] countTlsDraftsAs1_3 A flag indicating whether to return the enum value SSLVersion::TLS1_3 for all
		 * TLS 1.3 drafts. If set to "true" all TLS 1.3 draft values (i.e 0x7f0e - 0x7f1c, 0xfb17, 0xfb1a) will return
		 * SSLVersion::TLS1_3, otherwise the corresponding enum values will be returned. The default value is "false".
		 */
		SSLVersionEnum asEnum(bool countTlsDraftsAs1_3 = false);

		/**
		 * @return The numeric value of the SSL/TLs version
		 */
		uint16_t asUInt()
		{
			return m_SSLVersionValue;
		}

		/**
		 * @return A string representation of the SSL/TLS version. For example: for TLS 1.2 the string "TLS 1.2" is
		 * returned. If the numeric value is an invalid SSL/TLS version the string "Unknown" will be returned.
		 * @param[in] countTlsDraftsAs1_3 A flag indicating whether to return the string value "TLS 1.3" for all TLS 1.3
		 * drafts. If set to "true" all TLS 1.3 draft values (i.e 0x7f0e - 0x7f1c, 0xfb17, 0xfb1a) will return
		 * "TLS 1.3", otherwise the corresponding string values will be returned. The default value is "false".
		 */
		std::string toString(bool countTlsDraftsAs1_3 = false);

	private:
		uint16_t m_SSLVersionValue;

		// unimplemented empty c'tor
		SSLVersion();
	};

	/**
	 * SSL/TLS handshake message types
	 */
	enum SSLHandshakeType
	{
		/** Hello-request message type */
		SSL_HELLO_REQUEST = 0,
		/** Client-hello message type */
		SSL_CLIENT_HELLO = 1,
		/** Server-hello message type */
		SSL_SERVER_HELLO = 2,
		/** New-session-ticket message type */
		SSL_NEW_SESSION_TICKET = 4,
		/** End-of-early-data message type (TLS 1.3) */
		SSL_END_OF_EARLY_DATE = 5,
		/** Encrypted-extensions message type (TLS 1.3) */
		SSL_ENCRYPTED_EXTENSIONS = 8,
		/** Certificate message type */
		SSL_CERTIFICATE = 11,
		/** Server-key-exchange message type */
		SSL_SERVER_KEY_EXCHANGE = 12,
		/** Certificate-request message type */
		SSL_CERTIFICATE_REQUEST = 13,
		/** Server-hello-done message type */
		SSL_SERVER_DONE = 14,
		/** Certificate-verify message type */
		SSL_CERTIFICATE_VERIFY = 15,
		/** Client-key-exchange message type */
		SSL_CLIENT_KEY_EXCHANGE = 16,
		/** Finish message type */
		SSL_FINISHED = 20,
		/** Key-update message type (TLS 1.3) */
		SSL_KEY_UPDATE = 24,
		/** Unknown SSL handshake message */
		SSL_HANDSHAKE_UNKNOWN = 255
	};

	/**
	 * SSL/TLS alert levels
	 */
	enum SSLAlertLevel
	{
		/** Warning level alert */
		SSL_ALERT_LEVEL_WARNING = 1,
		/** Fatal level alert */
		SSL_ALERT_LEVEL_FATAL = 2,
		/** For encrypted alerts the level is unknown so this type will be returned */
		SSL_ALERT_LEVEL_ENCRYPTED = 255
	};

	/**
	 * SSL/TLS alert description types
	 */
	enum SSLAlertDescription
	{
		/** Close notify alert */
		SSL_ALERT_CLOSE_NOTIFY = 0,
		/** Unexpected message alert */
		SSL_ALERT_UNEXPECTED_MESSAGE = 10,
		/** Bad record MAC alert */
		SSL_ALERT_BAD_RECORD_MAC = 20,
		/** Decryption failed alert */
		SSL_ALERT_DECRYPTION_FAILED = 21,
		/**  */
		SSL_ALERT_RECORD_OVERFLOW = 22,
		/** Decompression failure alert */
		SSL_ALERT_DECOMPRESSION_FAILURE = 30,
		/** Handshake failure alert */
		SSL_ALERT_HANDSHAKE_FAILURE = 40,
		/** No certificate alert */
		SSL_ALERT_NO_CERTIFICATE = 41,
		/** Bad certificate alert */
		SSL_ALERT_BAD_CERTIFICATE = 42,
		/** Unsupported certificate */
		SSL_ALERT_UNSUPPORTED_CERTIFICATE = 43,
		/** Certificate revoked alert */
		SSL_ALERT_CERTIFICATE_REVOKED = 44,
		/** Certificate expired alert */
		SSL_ALERT_CERTIFICATE_EXPIRED = 45,
		/** Certificate unknown alert */
		SSL_ALERT_CERTIFICATE_UNKNOWN = 46,
		/** Illegal parameter alert */
		SSL_ALERT_ILLEGAL_PARAMETER = 47,
		/** Unknown CA alert */
		SSL_ALERT_UNKNOWN_CA = 48,
		/** Access denied alert */
		SSL_ALERT_ACCESS_DENIED = 49,
		/** Decode error alert */
		SSL_ALERT_DECODE_ERROR = 50,
		/** Decrypt error alert */
		SSL_ALERT_DECRYPT_ERROR = 51,
		/** Export restriction alert */
		SSL_ALERT_EXPORT_RESTRICTION = 60,
		/** Protocol version alert */
		SSL_ALERT_PROTOCOL_VERSION = 70,
		/** Insufficient security alert */
		SSL_ALERT_INSUFFICIENT_SECURITY = 71,
		/** Internal error alert */
		SSL_ALERT_INTERNAL_ERROR = 80,
		/** User cancelled alert */
		SSL_ALERT_USER_CANCELLED = 90,
		/** No negotiation alert */
		SSL_ALERT_NO_RENEGOTIATION = 100,
		/** Unsupported extension alert */
		SSL_ALERT_UNSUPPORTED_EXTENSION = 110,
		/** Encrtpyed alert (cannot determine its type) */
		SSL_ALERT_ENCRYPTED = 255
	};

	/**
	 * SSL/TLS key exchange algorithms
	 */
	enum SSLKeyExchangeAlgorithm
	{
		/** Null value */
		SSL_KEYX_NULL,
		/** RSA (Rivest-Shamir-Adleman) */
		SSL_KEYX_RSA,
		/** Diffie-Hellman */
		SSL_KEYX_DH,
		/** Diffie-Hellman ephemeral */
		SSL_KEYX_DHE,
		/** Elliptic curve Diffie�Hellman */
		SSL_KEYX_ECDH,
		/** Elliptic curve Diffie�Hellman ephemeral */
		SSL_KEYX_ECDHE,
		/** Fortezza Crypto Card */
		SSL_KEYX_FORTEZZA,
		/** Kerberos 5 */
		SSL_KEYX_KRB5,
		/**  Pre-Shared Key */
		SSL_KEYX_PSK,
		/** GOST */
		SSL_KEYX_GOST,
		/** Secure Remote Password */
		SSL_KEYX_SRP,
		/** PCT */
		SSL_KEYX_PCT,
		/** Unknown algorithm */
		SSL_KEYX_Unknown
	};

	/**
	 * SSL/TLS authentication algorithms
	 */
	enum SSLAuthenticationAlgorithm
	{
		/** Null value */
		SSL_AUTH_NULL,
		/** RSA (Rivest-Shamir-Adleman) */
		SSL_AUTH_RSA,
		/** Digital Signature Standard */
		SSL_AUTH_DSS,
		/** Anonymous */
		SSL_AUTH_anon,
		/** Diffie-Hellman based key-exchange protocol */
		SSL_AUTH_KEA,
		/** Kerberos 5 */
		SSL_AUTH_KRB5,
		/** Pre-Shared Key */
		SSL_AUTH_PSK,
		/** Elliptic Curve Digital Signature Algorithm */
		SSL_AUTH_ECDSA,
		/** GOST */
		SSL_AUTH_GOST,
		/** SHA-1 (Secure Hash Algorithm) */
		SSL_AUTH_SHA,
		/** PCT */
		SSL_AUTH_PCT,
		/** Diffie-Hellman ephemeral */
		SSL_AUTH_DHE,
		/** Unknown algorithm */
		SSL_AUTH_Unknown
	};

	/**
	 * SSL/TLS symmetric encryption algorithms
	 */
	enum SSLSymetricEncryptionAlgorithm
	{
		/** Null value */
		SSL_SYM_NULL,
		/** RC4_40 */
		SSL_SYM_RC4_40,
		/** RC4_128 */
		SSL_SYM_RC4_128,
		/** RC2_CBC_40 */
		SSL_SYM_RC2_CBC_40,
		/** IDEA_CBC */
		SSL_SYM_IDEA_CBC,
		/** DES40_CBC */
		SSL_SYM_DES40_CBC,
		/** DES_CBC */
		SSL_SYM_DES_CBC,
		/** 3DES_EDE_CBC */
		SSL_SYM_3DES_EDE_CBC,
		/** FORTEZZA_CBC */
		SSL_SYM_FORTEZZA_CBC,
		/** DES_CBC_40 */
		SSL_SYM_DES_CBC_40,
		/** AES_128_CBC */
		SSL_SYM_AES_128_CBC,
		/** AES_256_CBC */
		SSL_SYM_AES_256_CBC,
		/** CAMELLIA_128_CBC */
		SSL_SYM_CAMELLIA_128_CBC,
		/** CAMELLIA_128_GCM */
		SSL_SYM_CAMELLIA_128_GCM,
		/** CAMELLIA_256_GCM */
		SSL_SYM_CAMELLIA_256_GCM,
		/** RC4_56 */
		SSL_SYM_RC4_56,
		/** RC2_CBC_56 */
		SSL_SYM_RC2_CBC_56,
		/** GOST28147 */
		SSL_SYM_GOST28147,
		/** CAMELLIA_256_CBC */
		SSL_SYM_CAMELLIA_256_CBC,
		/** SEED_CBC */
		SSL_SYM_SEED_CBC,
		/** AES_128 */
		SSL_SYM_AES_128,
		/** AES_256 */
		SSL_SYM_AES_256,
		/** SSL_SYM_AES_128_GCM */
		SSL_SYM_AES_128_GCM,
		/** AES_256_GCM */
		SSL_SYM_AES_256_GCM,
		/** RC4_128_EXPORT40 */
		SSL_SYM_RC4_128_EXPORT40,
		/** RC2_CBC_128_CBC */
		SSL_SYM_RC2_CBC_128_CBC,
		/** IDEA_128_CBC */
		SSL_SYM_IDEA_128_CBC,
		/** DES_64_CBC */
		SSL_SYM_DES_64_CBC,
		/** DES_192_EDE3_CBC */
		SSL_SYM_DES_192_EDE3_CBC,
		/** RC4_64 */
		SSL_SYM_RC4_64,
		/** ARIA_128_CBC*/
		SSL_SYM_ARIA_128_CBC,
		/** ARIA_256_CBC */
		SSL_SYM_ARIA_256_CBC,
		/** ARIA_128_GCM */
		SSL_SYM_ARIA_128_GCM,
		/** ARIA_256_GCM */
		SSL_SYM_ARIA_256_GCM,
		/** CHACHA20_POLY1305 */
		SSL_SYM_CHACHA20_POLY1305,
		/** AES_128_CCM */
		SSL_SYM_AES_128_CCM,
		/** AES_128_CCM_8 */
		SSL_SYM_AES_128_CCM_8,
		/** Unknown algorithm */
		SSL_SYM_Unknown
	};

	/**
	 * SSL/TLS hashing algorithms
	 */
	enum SSLHashingAlgorithm
	{
		/** Null value */
		SSL_HASH_NULL,
		/** Message-Digest Algorithm */
		SSL_HASH_MD5,
		/** SHA-1 (Secure Hash Algorithm) */
		SSL_HASH_SHA,
		/** SHA-256 (Secure Hash Algorithm) */
		SSL_HASH_SHA256,
		/** GOST 28147 */
		SSL_HASH_GOST28147,
		/**  GOST R 34.11 */
		SSL_HASH_GOSTR3411,
		/** SHA-384 (Secure Hash Algorithm) */
		SSL_HASH_SHA384,
		/** CCM mode (Counter with CBC-MAC) */
		SSL_HASH_CCM,
		/** CCM mode (Counter with CBC-MAC) */
		SSL_HASH_CCM_8,
		/** Unknown algorithm */
		SSL_HASH_Unknown
	};

	/**
	 * SSL/TLS extension types
	 */
	enum SSLExtensionType
	{
		/** Server Name Indication extension */
		SSL_EXT_SERVER_NAME = 0,
		/** Maximum Fragment Length Negotiation extension */
		SSL_EXT_MAX_FRAGMENT_LENGTH = 1,
		/** Client Certificate URLs extension */
		SSL_EXT_CLIENT_CERTIFICATE_URL = 2,
		/** Trusted CA Indication extension */
		SSL_EXT_TRUSTED_CA_KEYS = 3,
		/** Truncated HMAC extension */
		SSL_EXT_TRUNCATED_HMAC = 4,
		/** Certificate Status Request extension */
		SSL_EXT_STATUS_REQUEST = 5,
		/** TLS User Mapping extension */
		SSL_EXT_USER_MAPPING = 6,
		/** Client Authorization  extension */
		SSL_EXT_CLIENT_AUTHZ = 7,
		/** Server Authorization extension */
		SSL_EXT_SERVER_AUTHZ = 8,
		/** Certificate Type extension */
		SSL_EXT_CERT_TYPE = 9,
		/** Supported Groups extension (renamed from "elliptic curves") */
		SSL_EXT_SUPPORTED_GROUPS = 10,
		/** Elliptic Curves Point Format extension */
		SSL_EXT_EC_POINT_FORMATS = 11,
		/** Secure Remote Password extension */
		SSL_EXT_SRP = 12,
		/** Signature Algorithms extension */
		SSL_EXT_SIGNATURE_ALGORITHMS = 13,
		/** Use Secure Real-time Transport Protocol extension */
		SSL_EXT_USE_SRTP = 14,
		/** TLS Heartbit extension */
		SSL_EXT_HEARTBEAT = 15,
		/** Application Layer Protocol Negotiation (ALPN) extension */
		SSL_EXT_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16,
		/** Status Request extension */
		SSL_EXT_STATUS_REQUEST_V2 = 17,
		/** Signed Certificate Timestamp extension */
		SSL_EXT_SIGNED_CERTIFICATE_TIMESTAMP = 18,
		/** Client Certificate Type extension */
		SSL_EXT_CLIENT_CERTIFICATE_TYPE = 19,
		/** Server Certificate Type extension */
		SSL_EXT_SERVER_CERTIFICATE_TYPE = 20,
		/** ClientHello Padding extension */
		SSL_EXT_PADDING = 21,
		/** Encrypt-then-MAC extension */
		SSL_EXT_ENCRYPT_THEN_MAC = 22,
		/** Extended Master Secret extension */
		SSL_EXT_EXTENDED_MASTER_SECRET = 23,
		/** Token Binding extension */
		SSL_EXT_TOKEN_BINDING = 24,
		/** SessionTicket TLS extension */
		SSL_EXT_SESSIONTICKET_TLS = 35,
		/** Pre-shared key (PSK) extension (TLS 1.3) */
		SSL_EXT_PRE_SHARED_KEY = 41,
		/** Early data extension (TLS 1.3) */
		SSL_EXT_EARLY_DATA = 42,
		/** Supported versions extension (TLS 1.3) */
		SSL_EXT_SUPPORTED_VERSIONS = 43,
		/** Cookie extension (TLS 1.3) */
		SSL_EXT_COOKIE = 44,
		/** Pre-Shared Key Exchange Modes extension (TLS 1.3) */
		SSL_EXT_PSK_KEY_EXCHANGE_MODES = 45,
		/** Certificate authorities extension (TLS 1.3) */
		SSL_EXT_CERTIFICATE_AUTHORITIES = 47,
		/** Old filters extension (TLS 1.3) */
		SSL_EXT_OLD_FILTERS = 48,
		/** Post handshake auth extension (TLS 1.3) */
		SSL_EXT_POST_HANDSHAKE_AUTH = 49,
		/** Signature algorithm cert extension (TLS 1.3) */
		SSL_EXT_SIGNATURE_ALGORITHM_CERT = 50,
		/** Key share extension (TLS 1.3) */
		SSL_EXT_KEY_SHARE = 51,
		/** Renegotiation Indication extension */
		SSL_EXT_RENEGOTIATION_INFO = 65281,
		/** Unknown extension */
		SSL_EXT_Unknown
	};

	/**
	 * SSL/TLS client certificate types
	 */
	enum SSLClientCertificateType
	{
		/** RSA_SIGN */
		SSL_CCT_RSA_SIGN = 1,
		/** DSS_SIGN */
		SSL_CCT_DSS_SIGN = 2,
		/** RSA_FIXED_DH */
		SSL_CCT_RSA_FIXED_DH = 3,
		/** DSS_FIXED_DH */
		SSL_CCT_DSS_FIXED_DH = 4,
		/** RSA_EPHEMERAL_DH_RESERVED */
		SSL_CCT_RSA_EPHEMERAL_DH_RESERVED = 5,
		/** DSS_EPHEMERAL_DH_RESERVED */
		SSL_CCT_DSS_EPHEMERAL_DH_RESERVED = 6,
		/** FORTEZZA_DMS_RESERVED */
		SSL_CCT_FORTEZZA_DMS_RESERVED = 20,
		/** ECDSA_SIGN */
		SSL_CCT_ECDSA_SIGN = 64,
		/** FIXED_ECDH */
		SSL_CCT_RSA_FIXED_ECDH = 65,
		/** ECDSA_FIXED_ECDH */
		SSL_CCT_ECDSA_FIXED_ECDH = 66,
		/** Unknown client certificate type */
		SSL_CCT_UNKNOWN
	};

}  // namespace vanhooks::net
// ---- end SSLCommon.h ----

// ---- begin Asn1Codec.h ----
#include <string>
#include <memory>
#include <typeinfo>
#include <stdexcept>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * An enum for representing ASN.1 tag class
	 */
	enum class Asn1TagClass : uint8_t
	{
		/** The Universal tag class */
		Universal = 0,
		/** The Application tag class */
		Application = 1,
		/** The Context-Specific tag class */
		ContextSpecific = 2,
		/** The Private tag class */
		Private = 3,
	};

	/**
	 * An enum for representing ASN.1 Universal tag types
	 */
	enum class Asn1UniversalTagType : uint8_t
	{
		/** The reserved identifier for the End-of-Contents marker in an indefinite length encoding */
		EndOfContent = 0,
		/** The universal tag type for Boolean */
		Boolean = 1,
		/** The universal tag type for Integer */
		Integer = 2,
		/** The universal tag type for Bit String */
		BitString = 3,
		/** The universal tag type for Octet String */
		OctetString = 4,
		/** The universal tag type for Null */
		Null = 5,
		/** The universal tag type for Object Identifier */
		ObjectIdentifier = 6,
		/** The universal tag type for Object Descriptor */
		ObjectDescriptor = 7,
		/** The universal tag type for External */
		External = 8,
		/** The universal tag type for Real */
		Real = 9,
		/** The universal tag type for Enumerated */
		Enumerated = 10,
		/** The universal tag type for Embedded-PDV */
		EmbeddedPDV = 11,
		/** The universal tag type for UTF8 String */
		UTF8String = 12,
		/** The universal tag type for Relative Object Identifier */
		RelativeObjectIdentifier = 13,
		/** The universal tag type for Time */
		Time = 14,
		/** A reserved value */
		Reserved = 15,
		/** The universal tag type Sequence */
		Sequence = 16,
		/** The universal tag type for Set */
		Set = 17,
		/** The universal tag type for Numeric String */
		NumericString = 18,
		/** The universal tag type for Printable String */
		PrintableString = 19,
		/** The universal tag type for T61String */
		T61String = 20,
		/** The universal tag type for Videotex String */
		VideotexString = 21,
		/** The universal tag type for IA5String */
		IA5String = 22,
		/** The universal tag type for UTC time */
		UTCTime = 23,
		/** The universal tag type for Generalized time */
		GeneralizedTime = 24,
		/** The universal tag type for GraphicString */
		GraphicString = 25,
		/** The universal tag type for VisibleString */
		VisibleString = 26,
		/** The universal tag type for GeneralString */
		GeneralString = 27,
		/** The universal tag type for UniversalString */
		UniversalString = 28,
		/** The universal tag type for CharacterString */
		CharacterString = 29,
		/** The universal tag type for BMPString */
		BMPString = 30,
		/** The universal tag type for Date */
		Date = 31,
		/** The universal tag type for Time of Day */
		TimeOfDay = 32,
		/** The universal tag type for Date-Time */
		DateTime = 33,
		/** The universal tag type for Duration */
		Duration = 34,
		/** The universal tag type for Object Identifier Internationalized Resource Identifier (IRI) */
		ObjectIdentifierIRI = 35,
		/** The universal tag type for Relative Object Identifier Internationalized Resource Identifier (IRI) */
		RelativeObjectIdentifierIRI = 36,
		/** A non-applicable value */
		NotApplicable = 255
	};

	/**
	 * @class Asn1Record
	 * Represents an ASN.1 record, as described in ITU-T Recommendation X.680:
	 * <https://www.itu.int/rec/T-REC-X.680/en>
	 *
	 * <https://en.wikipedia.org/wiki/ASN.1>
	 */
	class Asn1Record
	{
	public:
		/**
		 * A static method to decode a byte array into an Asn1Record
		 * @param data A byte array to decode
		 * @param dataLen The byte array length
		 * @param lazy Use lazy decoding, set to true by default. Lazy decoding entails delaying the decoding
		 * of the record value until it is accessed
		 * @return A smart pointer to the decoded ASN.1 record. If the byte stream is not a valid ASN.1 record
		 * an exception is thrown
		 */
		static std::unique_ptr<Asn1Record> decode(const uint8_t* data, size_t dataLen, bool lazy = true);

		/**
		 * Encode this record and convert it to a byte stream
		 * @return A vector of bytes representing the record
		 */
		std::vector<uint8_t> encode();

		/**
		 * @return The ASN.1 tag class
		 */
		Asn1TagClass getTagClass() const
		{
			return m_TagClass;
		}

		/**
		 * @return True if it's a constructed record, or false if it's a primitive record
		 */
		bool isConstructed() const
		{
			return m_IsConstructed;
		}

		/**
		 * @return The ASN.1 Universal tag type if the record is of class Universal, otherwise
		 * Asn1UniversalTagType#NotApplicable
		 */
		Asn1UniversalTagType getUniversalTagType() const;

		/**
		 * @return The ASN.1 tag type value
		 */
		uint8_t getTagType() const
		{
			return m_TagType;
		}

		/**
		 * @return The length of the record value
		 */
		size_t getValueLength() const
		{
			return m_ValueLength;
		}

		/**
		 * @return The total length of the record
		 */
		size_t getTotalLength() const
		{
			return m_TotalLength;
		}

		/**
		 * @return A string representation of the record
		 */
		std::string toString();

		/**
		 * A templated method that accepts a class derived from Asn1Record as its template argument and attempts
		 * to cast the current instance to that type
		 * @tparam Asn1RecordType The type to cast to
		 * @return A pointer to the type after casting
		 */
		template <class Asn1RecordType> Asn1RecordType* castAs()
		{
			auto result = dynamic_cast<Asn1RecordType*>(this);
			if (result == nullptr)
			{
				throw std::bad_cast();
			}
			return result;
		}

		virtual ~Asn1Record() = default;

	protected:
		Asn1TagClass m_TagClass = Asn1TagClass::Universal;
		bool m_IsConstructed = false;
		uint8_t m_TagType = 0;

		size_t m_ValueLength = 0;
		size_t m_TotalLength = 0;

		uint8_t* m_EncodedValue = nullptr;

		Asn1Record() = default;

		static Asn1Record* decodeInternal(const uint8_t* data, size_t dataLen, bool lazy);

		virtual void decodeValue(uint8_t* data, bool lazy) = 0;
		virtual std::vector<uint8_t> encodeValue() const = 0;

		static Asn1Record* decodeTagAndCreateRecord(const uint8_t* data, size_t dataLen, int& tagLen);
		int decodeLength(const uint8_t* data, size_t dataLen);
		void decodeValueIfNeeded();

		uint8_t encodeTag();
		std::vector<uint8_t> encodeLength() const;

		virtual std::vector<std::string> toStringList();

		friend class Asn1ConstructedRecord;
	};

	/**
	 * @class Asn1GenericRecord
	 * Represents a generic ASN.1 record, either of an unknown type or of a known type that doesn't
	 * have a dedicated parser yet
	 */
	class Asn1GenericRecord : public Asn1Record
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a generic record
		 * @param tagClass The record tag class
		 * @param isConstructed A flag to indicate if the record is constructed or primitive
		 * @param tagType The record tag type value
		 * @param value A byte array of the tag value
		 * @param valueLen The length of the value byte array
		 */
		Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value,
		                  size_t valueLen);

		/**
		 * A constructor to create a generic record
		 * @param tagClass The record tag class
		 * @param isConstructed A flag to indicate if the record is constructed or primitive
		 * @param tagType The record tag type value
		 * @param value A string representing the tag value
		 */
		Asn1GenericRecord(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const std::string& value);

		~Asn1GenericRecord() override;

		/**
		 * @return A pointer to the tag value
		 */
		const uint8_t* getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		}

	protected:
		Asn1GenericRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

	private:
		uint8_t* m_Value = nullptr;

		void init(Asn1TagClass tagClass, bool isConstructed, uint8_t tagType, const uint8_t* value, size_t valueLen);
	};

	/**
	 * @class Asn1ConstructedRecord
	 * Represents a constructed ASN.1 record, which is a record that has sub-records
	 */
	class Asn1ConstructedRecord : public Asn1Record
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a constructed record
		 * @param tagClass The record tag class
		 * @param tagType The record tag type value
		 * @param subRecords A list of sub-records to assign as the record value
		 */
		explicit Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType,
		                               const std::vector<Asn1Record*>& subRecords);

		/**
		 * A constructor to create a constructed record
		 * @param tagClass The record tag class
		 * @param tagType The record tag type value
		 * @param subRecords A PointerVector of sub-records to assign as the record value
		 */
		explicit Asn1ConstructedRecord(Asn1TagClass tagClass, uint8_t tagType,
		                               const PointerVector<Asn1Record>& subRecords);

		/**
		 * @return A reference to the list of sub-records. It's important to note that any modifications made to
		 * this list will directly affect the internal structure
		 */
		PointerVector<Asn1Record>& getSubRecords()
		{
			decodeValueIfNeeded();
			return m_SubRecords;
		};

	protected:
		Asn1ConstructedRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

		template <typename Iterator> void init(Asn1TagClass tagClass, uint8_t tagType, Iterator begin, Iterator end)
		{
			m_TagType = tagType;
			m_TagClass = tagClass;
			m_IsConstructed = true;

			size_t recordValueLength = 0;
			for (Iterator recordIter = begin; recordIter != end; ++recordIter)
			{
				auto encodedRecord = (*recordIter)->encode();
				auto copyRecord = Asn1Record::decode(encodedRecord.data(), encodedRecord.size(), false);
				m_SubRecords.pushBack(std::move(copyRecord));
				recordValueLength += encodedRecord.size();
			}

			m_ValueLength = recordValueLength;
			m_TotalLength = recordValueLength + 1 + (m_ValueLength < 128 ? 1 : 2);
		}

	private:
		PointerVector<Asn1Record> m_SubRecords;
	};

	/**
	 * @class Asn1SequenceRecord
	 * Represents an ASN.1 record with a value of type Sequence
	 */
	class Asn1SequenceRecord : public Asn1ConstructedRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Sequence
		 * @param subRecords A list of sub-records to assign as the record value
		 */
		explicit Asn1SequenceRecord(const std::vector<Asn1Record*>& subRecords);

		/**
		 * A constructor to create a record of type Sequence
		 * @param subRecords A PointerVector of sub-records to assign as the record value
		 */
		explicit Asn1SequenceRecord(const PointerVector<Asn1Record>& subRecords);

	private:
		Asn1SequenceRecord() = default;
	};

	/**
	 * @class Asn1SetRecord
	 * Represents an ASN.1 record with a value of type Set
	 */
	class Asn1SetRecord : public Asn1ConstructedRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Set
		 * @param subRecords A list of sub-records to assign as the record value
		 */
		explicit Asn1SetRecord(const std::vector<Asn1Record*>& subRecords);

		/**
		 * A constructor to create a record of type Set
		 * @param subRecords A PointerVector of sub-records to assign as the record value
		 */
		explicit Asn1SetRecord(const PointerVector<Asn1Record>& subRecords);

	private:
		Asn1SetRecord() = default;
	};

	/**
	 * @class Asn1PrimitiveRecord
	 * Represents a primitive ASN.1 record, meaning a record that doesn't have sub-records.
	 * This is an abstract class that cannot be instantiated
	 */
	class Asn1PrimitiveRecord : public Asn1Record
	{
		friend class Asn1Record;

	protected:
		Asn1PrimitiveRecord() = default;
		explicit Asn1PrimitiveRecord(Asn1UniversalTagType tagType);
	};

	/**
	 * @class Asn1IntegerRecord
	 * Represents an ASN.1 record with a value of type Integer
	 */
	class Asn1IntegerRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Integer
		 * @param value An integer to set as the record value
		 */
		explicit Asn1IntegerRecord(uint32_t value);

		/**
		 * @return The integer value of this record
		 */
		uint32_t getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		}

	protected:
		Asn1IntegerRecord() = default;

		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		uint32_t m_Value = 0;
	};

	/**
	 * @class Asn1EnumeratedRecord
	 * Represents an ASN.1 record with a value of type Enumerated
	 */
	class Asn1EnumeratedRecord : public Asn1IntegerRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Enumerated
		 * @param value An integer to set as the record value
		 */
		explicit Asn1EnumeratedRecord(uint32_t value);

	private:
		Asn1EnumeratedRecord() = default;
	};

	/**
	 * @class Asn1OctetStringRecord
	 * Represents an ASN.1 record with a value of type Octet String
	 */
	class Asn1OctetStringRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Octet String from a printable value
		 * @param value A string to set as the record value
		 */
		explicit Asn1OctetStringRecord(const std::string& value);

		/**
		 * A constructor to create a record of type Octet String from a non-printable value
		 * @param value A byte array to set as the record value
		 * @param valueLength The length of the byte array
		 */
		explicit Asn1OctetStringRecord(const uint8_t* value, size_t valueLength);

		/**
		 * @return The string value of this record
		 */
		std::string getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		};

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		std::string m_Value;
		bool m_IsPrintable = true;

		Asn1OctetStringRecord() = default;
	};

	/**
	 * @class Asn1BooleanRecord
	 * Represents an ASN.1 record with a value of type Boolean
	 */
	class Asn1BooleanRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Boolean
		 * @param value A boolean to set as the record value
		 */
		explicit Asn1BooleanRecord(bool value);

		/**
		 * @return The boolean value of this record
		 */
		bool getValue()
		{
			decodeValueIfNeeded();
			return m_Value;
		};

	protected:
		void decodeValue(uint8_t* data, bool lazy) override;
		std::vector<uint8_t> encodeValue() const override;

		std::vector<std::string> toStringList() override;

	private:
		Asn1BooleanRecord() = default;

		bool m_Value = false;
	};

	/**
	 * @class Asn1NullRecord
	 * Represents an ASN.1 record with a value of type Null
	 */
	class Asn1NullRecord : public Asn1PrimitiveRecord
	{
		friend class Asn1Record;

	public:
		/**
		 * A constructor to create a record of type Null
		 */
		Asn1NullRecord();

	protected:
		void decodeValue(uint8_t* data, bool lazy) override
		{}
		std::vector<uint8_t> encodeValue() const override
		{
			return {};
		}
	};
}  // namespace vanhooks::net
// ---- end Asn1Codec.h ----

// ---- begin SSLHandshake.h ----
#include <utility>

/**
 * @file
 * See detailed explanation of the TLS/SSL protocol support in VanHooks in SSLLayer.h
 */

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class SSLCipherSuite
	 * Represents a cipher-suite and enables access all information about it such as all algorithms it encapsulates,
	 * its ID (as appears in the client-hello or server-hello messages),
	 * its name (e.g "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA") etc. VanHooks contains static instances of this type
	 * for all known cipher-suites and enables access to them through name or ID (see getCipherSuiteByID() and
	 * getCipherSuiteByName() ). List of cipher-suite was taken from here:
	 * http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
	 */
	class SSLCipherSuite
	{
	public:
		/**
		 * A c'tor for this class, should never be used by a user
		 * @param[in] id Cipher-suite ID
		 * @param[in] keyExAlg Key-exchange algorithm used in this cipher-suite
		 * @param[in] authAlg Authentication algorithm used in this cipher-suite
		 * @param[in] symKeyAlg Symmetric key algorithm used in this cipher-suite
		 * @param[in] MACAlg MAC algorithm used in this cipher-suite
		 * @param[in] name String representation of this cipher-suite
		 */
		SSLCipherSuite(uint16_t id, SSLKeyExchangeAlgorithm keyExAlg, SSLAuthenticationAlgorithm authAlg,
		               SSLSymetricEncryptionAlgorithm symKeyAlg, SSLHashingAlgorithm MACAlg, const char* name)
		    : m_Id(id), m_KeyExAlg(keyExAlg), m_AuthAlg(authAlg), m_SymKeyAlg(symKeyAlg), m_MACAlg(MACAlg), m_Name(name)
		{}

		/**
		 * @return Cipher-suite ID
		 */
		uint16_t getID() const
		{
			return m_Id;
		}

		/**
		 * @return String representation of this cipher-suite
		 */
		std::string asString() const
		{
			return m_Name;
		}

		/**
		 * @return Key-exchange algorithm used in this cipher-suite
		 */
		SSLKeyExchangeAlgorithm getKeyExchangeAlg() const
		{
			return m_KeyExAlg;
		}

		/**
		 * @return Authentication algorithm used in this cipher-suite
		 */
		SSLAuthenticationAlgorithm getAuthAlg() const
		{
			return m_AuthAlg;
		}

		/**
		 * @return Symmetric key algorithm used in this cipher-suite
		 */
		SSLSymetricEncryptionAlgorithm getSymKeyAlg() const
		{
			return m_SymKeyAlg;
		}

		/**
		 * @return MAC algorithm used in this cipher-suite
		 */
		SSLHashingAlgorithm getMACAlg() const
		{
			return m_MACAlg;
		}

		/**
		 * A static method that returns a cipher-suite instance by ID
		 * @param[in] id Cipher-suite ID
		 * @return A cipher-suite instance matching this ID or nullptr if ID not found
		 */
		static SSLCipherSuite* getCipherSuiteByID(uint16_t id);

		/**
		 *  A static method that returns a cipher-suite instance by name
		 *  @param[in] name Cipher-suite name (e.g "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA")
		 *  @return A cipher-suite instance matching this name or nullptr if name not found
		 */
		static SSLCipherSuite* getCipherSuiteByName(std::string name);

	private:
		uint16_t m_Id;
		SSLKeyExchangeAlgorithm m_KeyExAlg;
		SSLAuthenticationAlgorithm m_AuthAlg;
		SSLSymetricEncryptionAlgorithm m_SymKeyAlg;
		SSLHashingAlgorithm m_MACAlg;
		std::string m_Name;
	};

	/**
	 * @class SSLExtension
	 * Represents a SSL/TLS extension. This is a base class that can represent any type of extension. Inherited classes
	 * may contain parsing logic for specific extensions. This class provides capabilities such as getting the extension
	 * type, length and viewing the extension data as raw (byte array)
	 */
	class SSLExtension
	{
	public:
		/**
		 * C'tor for this class
		 * @param[in] data The raw data for the extension
		 */
		explicit SSLExtension(uint8_t* data);

		virtual ~SSLExtension()
		{}

		/**
		 * @return The type of the extension as enum
		 */
		SSLExtensionType getType() const;

		/**
		 * @return The type of the extension as a numeric value
		 */
		uint16_t getTypeAsInt() const;

		/**
		 * @return The length of the extension data in bytes (not including the type and length fields)
		 */
		uint16_t getLength() const;

		/**
		 * @return The total length of the extension, including type and length fields and the extension data field
		 */
		uint16_t getTotalLength() const;

		/**
		 * @return A pointer to the raw data of the extension
		 */
		uint8_t* getData() const;

	protected:
		/**
		 * @struct SSLExtensionStruct
		 * Represents the common fields of the extension
		 */
		struct SSLExtensionStruct
		{
			/** Extension type */
			uint16_t extensionType;
			/** Extension length */
			uint16_t extensionDataLength;
			/** Extension data as raw (byte array) */
			uint8_t extensionData[];
		};

		uint8_t* m_RawData;

		SSLExtensionStruct* getExtensionStruct() const
		{
			return (SSLExtensionStruct*)m_RawData;
		}
	};

	/**
	 * @class SSLServerNameIndicationExtension
	 * Represents SSL/TLS Server Name Indication extension. Inherits from SSLExtension and add parsing of the hostname
	 * written in the extension data
	 */
	class SSLServerNameIndicationExtension : public SSLExtension
	{
	public:
		/**
		 * C'tor for this class
		 * @param[in] data The raw data for the extension
		 */
		explicit SSLServerNameIndicationExtension(uint8_t* data) : SSLExtension(data)
		{}

		/**
		 * @return The hostname written in the extension data
		 */
		std::string getHostName() const;
	};

	/**
	 * @class SSLSupportedVersionsExtension
	 * Represents TLS Supported Versions extension. Inherits from SSLExtension and adds parsing of the list
	 * of supported versions mentioned in the extension data
	 */
	class SSLSupportedVersionsExtension : public SSLExtension
	{
	public:
		/**
		 * C'tor for this class
		 * @param[in] data The raw data for the extension
		 */
		explicit SSLSupportedVersionsExtension(uint8_t* data) : SSLExtension(data)
		{}

		/**
		 * @return The list of supported versions mentioned in the extension data
		 */
		std::vector<SSLVersion> getSupportedVersions() const;
	};

	/**
	 * @class TLSSupportedGroupsExtension
	 * Represents TLS Supported Groups extension. Inherits from SSLExtension and adds parsing of the
	 * supported groups (Elliptic Curves) mentioned in the extension data
	 */
	class TLSSupportedGroupsExtension : public SSLExtension
	{
	public:
		/**
		 * C'tor for this class
		 * @param[in] data The raw data for the extension
		 */
		explicit TLSSupportedGroupsExtension(uint8_t* data) : SSLExtension(data)
		{}

		/**
		 * @return A vector of the supported groups (also known as "Elliptic Curves")
		 */
		std::vector<uint16_t> getSupportedGroups() const;
	};

	/**
	 * @class TLSECPointFormatExtension
	 * Represents TLS EC (Elliptic Curves) Point Format extension. Inherits from SSLExtension and adds parsing of the
	 * EC point formats mentioned in the extension data
	 */
	class TLSECPointFormatExtension : public SSLExtension
	{
	public:
		/**
		 * C'tor for this class
		 * @param[in] data The raw data for the extension
		 */
		explicit TLSECPointFormatExtension(uint8_t* data) : SSLExtension(data)
		{}

		/**
		 * @return A vector of the elliptic curves point formats
		 */
		std::vector<uint8_t> getECPointFormatList() const;
	};

	/**
	 * @class SSLx509Certificate
	 * Represents a x509v3 certificate. the SSLCertificateMessage class returns an instance of this class as the
	 * certificate. Currently this class doesn't do much as it doesn't parse the certificate. It only acts as container
	 * to the raw data and returns general info as data as raw, length, etc. In the future I may add full parsing of the
	 * certificate
	 */
	class SSLx509Certificate
	{
	public:
		/**
		 * C'tor for this class
		 * @param[in] data The raw data of the certificate
		 * @param[in] dataLen The length in bytes of the raw data
		 * @param[in] allDataExists Certificate messages usually spread on more than 1 packet. So a certificate is
		 * likely to split between 2 packets or more. This field indicates whether the raw data contains all
		 * certificate data of just a part of it
		 */
		SSLx509Certificate(uint8_t* data, size_t dataLen, bool allDataExists)
		    : m_Data(data), m_DataLen(dataLen), m_AllDataExists(allDataExists)
		{}

		/**
		 * @return A pointer to the raw data
		 */
		uint8_t* getData() const
		{
			return m_Data;
		}

		/**
		 * @return Raw data length
		 */
		size_t getDataLength() const
		{
			return m_DataLen;
		}

		/**
		 * @return The root ASN.1 record of the certificate data. All of the certificate data will be under this record.
		 * If the Root ASN.1 record is malformed, an exception is thrown
		 */
		Asn1SequenceRecord* getRootAsn1Record();

		/**
		 * Certificate messages usually spread on more than 1 packet. So a certificate is likely to split between 2
		 * packets or more. This method provides an indication whether all certificate data exists or only part of it
		 * @return True if this data contains all certificate data, false otherwise
		 */
		bool allDataExists() const
		{
			return m_AllDataExists;
		}

	private:
		std::unique_ptr<Asn1Record> m_Asn1Record;
		uint8_t* m_Data;
		size_t m_DataLen;
		bool m_AllDataExists;
	};

	class SSLHandshakeLayer;

	/**
	 * @class SSLHandshakeMessage
	 * A base class for SSL/TLS handshake messages. This is an abstract class and cannot be instantiated. SSL/TLS
	 * handshake messages are contained in SSLHandshakeLayer, meaning a SSLHandshakeLayer instance can contain one or
	 * more SSLHandshakeMessage instances. For example: one SSLHandshakeLayer may contain a server-hello, certificate,
	 * server-key-exchange, and server-hello-done messages (although it's not such a common case, most handshake layers
	 * contain 1 handshake message only)
	 */
	class SSLHandshakeMessage
	{
	public:
		virtual ~SSLHandshakeMessage()
		{}

		/**
		 * A factory method for creating instances of handshake messages from raw data
		 * @param[in] data The raw data containing 1 handshake message
		 * @param[in] dataLen Raw data length in bytes
		 * @param[in] container A pointer to the SSLHandshakeLayer instance which will contain the created message.
		 * This parameter is required because the handshake message includes a pointer to its container
		 */
		static SSLHandshakeMessage* createHandshakeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

		/**
		 * @return The handshake message type
		 */
		virtual SSLHandshakeType getHandshakeType() const;

		/**
		 * @return The handshake message length in bytes. Notice that sometimes the handshake message is divided between
		 * several packets, in this case this method will return the length of part of the message in the current packet
		 */
		virtual size_t getMessageLength() const;

		/**
		 * @return True if current packet contains the entire message or false otherwise. This method is important
		 * because sometimes handshake messages are divided in consequent packets (happens a lot in certificate messages
		 * which usually contain several KB of data which is larger than standard packet size, so the message is divided
		 * between several packets)
		 */
		virtual bool isMessageComplete() const;

		/**
		 * @return A pointer to the SSLHandshakeLayer instance containing this message
		 */
		SSLHandshakeLayer* getContainingLayer() const
		{
			return m_Container;
		}

		/**
		 * @return A string representation of the message type (e.g "Client Hello message")
		 */
		virtual std::string toString() const = 0;

	protected:
		SSLHandshakeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

		uint8_t* m_Data;
		size_t m_DataLen;
		SSLHandshakeLayer* m_Container;
	};

	/**
	 * @class SSLClientHelloMessage
	 * Represents a client-hello message (type 1). Inherits from SSLHandshakeMessage and adds parsing of all fields
	 * of this message including the message extensions, cipher-suite list, etc.
	 */
	class SSLClientHelloMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * @struct ClientHelloTLSFingerprint
		 * A struct that contains all the elements needed for creating a Client Hello TLS fingerprinting:
		 * TLS version, a list of Cipher Suite IDs, a list of Extensions IDs, a list of support groups and a list of
		 * EC point formats.
		 * You can read more about this in SSLClientHelloMessage#generateTLSFingerprint().
		 * This struct contains methods to extract the TLS fingerprint itself: toString() and toMD5()
		 */
		struct ClientHelloTLSFingerprint
		{
			/** TLS version */
			uint16_t tlsVersion;
			/** A list of Cipher Suite IDs */
			std::vector<uint16_t> cipherSuites;
			/** A list of extension IDs */
			std::vector<uint16_t> extensions;
			/** A list of Suppotred Groups taken from the "supported groups" TLS extension (if exist in the message) */
			std::vector<uint16_t> supportedGroups;
			/** A list of EC point formats taken from the "EC point formats" TLS extension (if exist in the message) */
			std::vector<uint8_t> ecPointFormats;

			/**
			 * @return A string representing the TLS fingerprint, for example:
			 * <b>771,4866-4867-4865-255,0-11-10-35-22-23-13-43-45-51,29-23-30-25-24,0-1-2</b>
			 *
			 * This string has the following format:
			 * <b>TLSVersion,CipherSuiteIDs,ExtensionIDs,SupportedGroups,ECPointFormats</b>
			 *
			 * The extension IDs, supported groups and EC point formats are each separated by a "-".
			 * If the message doesn't include the "supported groups" or "EC point formats" extensions, they will be
			 * replaced by an empty string for example: <b>771,4866-4867-4865-255,0-11-10-35-22-23-13-43-45-51,,</b>
			 */
			std::string toString();

			/**
			 * @return An MD5 hash of the string generated by toString()
			 */
			std::string toMD5();

			/**
			 * @return A pair of the string and MD5 hash (string is first, MD5 is second).
			 * If you want both this method is more efficient than calling toString() and toMD5() separately
			 */
			std::pair<std::string, std::string> toStringAndMD5();
		};

		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and shouldn't be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLClientHelloMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

		virtual ~SSLClientHelloMessage()
		{}

		/**
		 * @return A struct containing common fields for client-hello and server-hello messages. Notice this points
		 * directly to the data, so every change will change the actual packet data
		 */
		ssl_tls_client_server_hello* getClientHelloHeader() const
		{
			return (ssl_tls_client_server_hello*)m_Data;
		}

		/**
		 * @return Handshake SSL/TLS version (notice it may be different than SSLLayer#getRecordVersion(). Each
		 * client-hello or server-hello message has both record version and handshake version and they may differ from
		 * one another)
		 */
		SSLVersion getHandshakeVersion() const;

		/**
		 * @return Session ID length in bytes. If server-hello message doesn't include session ID 0 will be returned
		 */
		uint8_t getSessionIDLength() const;

		/**
		 * @return Session ID as byte array. If server-hello message doesn't include session ID nullptr will be returned
		 */
		uint8_t* getSessionID() const;

		/**
		 * @return The number of cipher-suites included in this message
		 */
		int getCipherSuiteCount() const;

		/**
		 * Get a pointer to a cipher-suite by index. The cipher-suites are numbered according to their order of
		 * appearance in the message. If index is out of bounds (less than 0 or larger than total amount of cipher
		 * suites) nullptr will be returned. nullptr will also be returned if the cipher-suite ID is unknown. If you
		 * still want to get the cipher-suite ID you can use getCipherSuiteID()
		 * @param[in] index The index of the cipher-suite to return
		 * @return The pointer to the cipher-suite object or nullptr if index is out of bounds
		 */
		SSLCipherSuite* getCipherSuite(int index) const;

		/**
		 * Get the cipher-suite ID by index. This method just parses the ID from the client-hello message and returns
		 * it. To get more information on the cipher-suite you can use the getCipherSuite() method
		 * @param[in] index The index of the cipher-suite to return
		 * @param[out] isValid Set to "true" if parsing succeeded and the return value is valid or "false" if:
		 * (1) the index is out-of-bounds (less than 0 or larger than total amount of cipher suites) or (2) the parsing
		 * failed. If the value is "false" the return value can be ignored
		 * @return The cipher-suite ID if "isValid" is set to "true". If "isValid" is set to "false" the return value
		 * can be ignored
		 */
		uint16_t getCipherSuiteID(int index, bool& isValid) const;

		/**
		 * @return The value of the compression method byte
		 */
		uint8_t getCompressionMethodsValue() const;

		/**
		 * @return The number of extensions in this message
		 */
		int getExtensionCount() const;

		/**
		 * @return The size (in bytes) of all extensions data in this message. Extracted from the "extensions length"
		 * field
		 */
		uint16_t getExtensionsLength() const;

		/**
		 * Get a pointer to an extension by index. The extensions are numbered according to their order of appearance
		 * in the message. If index is out of bounds (less than 0 or larger than total amount of extensions) nullptr
		 * will be returned
		 * @param[in] index The index of the extension to return
		 * @return The pointer to the extension or nullptr if index is out of bounds
		 */
		SSLExtension* getExtension(int index) const;

		/**
		 * Get a pointer to an extension by numeric type field. Every extension has a 2-byte numeric value representing
		 * its type (for example: renegotiation info extension type is 0x1ff). This method gets the type and returns a
		 * pointer to the extension object
		 * @param[in] type The 2-byte numeric type of the extension
		 * @return A pointer to the extension object of nullptr if this type doesn't exist in this message
		 */
		SSLExtension* getExtensionOfType(uint16_t type) const;

		/**
		 * Get a pointer to an extension by its enum type
		 * @param[in] type The type of extension to return
		 * @return A pointer to the extension object or nullptr if this type doesn't exist in this message
		 */
		SSLExtension* getExtensionOfType(SSLExtensionType type) const;

		/**
		 * Get a pointer to an extension by its class type. This is a templated method that is used with the type of the
		 * requested extension and returns the first extension instance of this type
		 * @return A pointer to the extension object or nullptr if this extension type doesn't exist in this message
		 *
		 */
		template <class TExtension> TExtension* getExtensionOfType() const;

		/**
		 * TLS fingerprinting is a way to identify client applications using the details in the TLS Client Hello packet.
		 * It was initially introduced by Lee Brotherston in his 2015 research:
		 * <https://blog.squarelemon.com/tls-fingerprinting/> This implementation of TLS fingerprint is a C++ version of
		 * Salesforce's JA3 open source project (originally written in Python and Zeek):
		 * <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>
		 * @return A SSLClientHelloMessage#ClientHelloTLSFingerprint struct that contains all the elements needed for
		 * creating a TLS fingerprint out of this Client Hello message. This struct has also methods to extract the TLS
		 * fingerprint itself in a string or MD5 formats
		 */
		ClientHelloTLSFingerprint generateTLSFingerprint() const;

		// implement abstract methods

		std::string toString() const;

	private:
		PointerVector<SSLExtension> m_ExtensionList;
	};

	/**
	 * @class SSLServerHelloMessage
	 * Represents SSL/TLS server-hello message (type 2). Inherits from SSLHandshakeMessage and adds parsing of all
	 * fields of this message including the message extensions, cipher-suite, etc.
	 */
	class SSLServerHelloMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * @struct ServerHelloTLSFingerprint
		 * A struct that contains all the elements needed for creating a Server Hello TLS fingerprinting:
		 * TLS version, Cipher Suite ID, and a list of Extensions IDs.
		 * You can read more about this in SSLServerHelloMessage#generateTLSFingerprint().
		 * This struct contains methods to extract the TLS fingerprint itself: toString() and toMD5()
		 */
		struct ServerHelloTLSFingerprint
		{
			/** TLS version */
			uint16_t tlsVersion;
			/** Cipher Suite ID */
			uint16_t cipherSuite;
			/** A list of extension IDs */
			std::vector<uint16_t> extensions;

			/**
			 * @return A string representing the TLS fingerprint, for example: <b>771,49195,65281-16-11</b>
			 *
			 * This string has the following format: <b>TLSVersion,Cipher,Extensions</b>
			 *
			 * The extension ID are separated with a "-"
			 */
			std::string toString();

			/**
			 * @return An MD5 hash of the string generated by toString()
			 */
			std::string toMD5();

			/**
			 * @return A pair of the string and MD5 hash (string is first, MD5 is second).
			 * If you want both this method is more efficient than calling toString() and toMD5() separately
			 */
			std::pair<std::string, std::string> toStringAndMD5();
		};

		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and shouldn't be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLServerHelloMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

		virtual ~SSLServerHelloMessage()
		{}

		/**
		 * @return A struct containing common fields for client-hello and server-hello messages. Notice this points
		 * directly to the data, so every change will change the actual packet data
		 */
		ssl_tls_client_server_hello* getServerHelloHeader() const
		{
			return (ssl_tls_client_server_hello*)m_Data;
		}

		/**
		 * @return Handshake SSL/TLS version (notice it may be different than SSLLayer#getRecordVersion(). Each
		 * client-hello or server-hello message has both record version and handshake version and they may differ from
		 * one another).
		 *
		 * <b>NOTE:</b> for TLS 1.3 the handshake version written in ssl_tls_client_server_hello::handshakeVersion is
		 * still TLS 1.2, so a special check is made here see if a SupportedVersions extension exists and if so extract
		 * the version from it. This is the most straight-forward way to detect TLS 1.3.
		 */
		SSLVersion getHandshakeVersion() const;

		/**
		 * @return Session ID length in bytes. If server-hello message doesn't include session ID 0 will be returned
		 */
		uint8_t getSessionIDLength() const;

		/**
		 * @return Session ID as byte array. If server-hello message doesn't include session ID nullptr will be returned
		 */
		uint8_t* getSessionID() const;

		/**
		 * @return A pointer to the cipher suite encapsulated in this message (server-hello message contains one
		 * cipher-suite, the one that will be used to for encryption between client and server). May return nullptr
		 * if the parsing of the message failed or the cipher-suite ID is unknown. If you still want to get the
		 * cipher-suite ID you can use the getCipherSuiteID() method
		 */
		SSLCipherSuite* getCipherSuite() const;

		/**
		 * Get the cipher-suite ID. This method just parses the ID from the server-hello message and returns it.
		 * To get more information on the cipher-suite you can use the getCipherSuite() method
		 * @param[out] isValid Set to "true" if parsing succeeded and the return value is valid or "false" otherwise.
		 * If the value is "false" the return value can be ignored
		 * @return The cipher-suite ID if "isValid" is set to "true". If "isValid" is set to "false" the return value
		 * can be ignored
		 */
		uint16_t getCipherSuiteID(bool& isValid) const;

		/**
		 * @return The value of the compression method byte
		 */
		uint8_t getCompressionMethodsValue() const;

		/**
		 * @return The number of extensions in this message
		 */
		int getExtensionCount() const;

		/**
		 * @return The size (in bytes) of all extensions data in this message. Extracted from the "extensions length"
		 * field
		 */
		uint16_t getExtensionsLength() const;

		/**
		 * Get a pointer to an extension by index. The extensions are numbered according to their order of appearance
		 * in the message. If index is out of bounds (less than 0 or larger than total amount of extensions) nullptr
		 * will be returned
		 * @param[in] index The index of the extension to return
		 * @return The pointer to the extension or nullptr if index is out of bounds
		 */
		SSLExtension* getExtension(int index) const;

		/**
		 * Get a pointer to an extension by numeric type field. Every extension has a 2-byte numeric value representing
		 * its type (for example: renegotiation info extension type is 0x1ff). This method gets the type and returns a
		 * pointer to the extension object
		 * @param[in] type The 2-byte numeric type of the extension
		 * @return A pointer to the extension object of nullptr if this type doesn't exist in this message
		 */
		SSLExtension* getExtensionOfType(uint16_t type) const;

		/**
		 * Get a pointer to an extension by its enum type
		 * @param[in] type The type of extension to return
		 * @return A pointer to the extension object or nullptr if this type doesn't exist in this message
		 */
		SSLExtension* getExtensionOfType(SSLExtensionType type) const;

		/**
		 * Get a pointer to an extension by its class type. This is a templated method that is used with the type of the
		 * requested extension and returns the first extension instance of this type
		 * @return A pointer to the extension object or nullptr if this extension type doesn't exist in this message
		 *
		 */
		template <class TExtension> TExtension* getExtensionOfType() const;

		/**
		 * ServerHello TLS fingerprinting is a way to fingerprint TLS Server Hello messages. In conjunction with
		 * ClientHello TLS fingerprinting it can assist in identifying specific client-server communication (for
		 * example: a malware connecting to its backend server).
		 * ServerHello TLS fingerprinting was introduced in Salesforce's JA3S open source project:
		 * <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>
		 * This implementation is a C++ version of Salesforce's JAS3 (originally written in Python and Zeek)
		 * @return A SSLServerHelloMessage#ServerHelloTLSFingerprint struct that contains all the elements needed for
		 * creating a TLS fingerprint out of this Server Hello message. This struct has also methods to extract the TLS
		 * fingerprint itself in a string or MD5 formats
		 */
		ServerHelloTLSFingerprint generateTLSFingerprint() const;

		// implement abstract methods

		std::string toString() const;

	private:
		PointerVector<SSLExtension> m_ExtensionList;
	};

	/**
	 * @class SSLCertificateMessage
	 * Represents SSL/TLS certificate message (type 11). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as extracting the certificates data. Notice that in most cases this message is spread over
	 * more than 1 packet as its size is too big for a single packet. So SSLCertificateMessage instance will be created
	 * just for the first part of the message - the one encapsulated in the first packet. Other parts (encapsulated in
	 * the following packets) won't be recognized as SSLCertificateMessage messages
	 */
	class SSLCertificateMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLCertificateMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

		virtual ~SSLCertificateMessage()
		{}

		/**
		 * @return The number of certificates encapsulated in this message (as written in the 'length' field of the
		 * message). Notice that because the message may spread over several packets, not all certificates will
		 * necessarily be in this packet. So, for example, there may be a case where this method return 3 (message
		 * contains 3 certificates) but this message actually contains only 1 certificate as the other 2 are spread over
		 * the other packets
		 */
		int getNumOfCertificates() const;

		/**
		 * Get a certificate by index
		 * @param[in] index The index of the certificate to retrieve
		 * @return A pointer to the certificate object. Notice that if index < 0 or index > num of certificates
		 * encapsulated in current packet a nullptr value will be returned
		 */
		SSLx509Certificate* getCertificate(int index) const;

		// implement abstract methods

		std::string toString() const;

	private:
		PointerVector<SSLx509Certificate> m_CertificateList;
	};

	/**
	 * @class SSLHelloRequestMessage
	 * Represents SSL/TLS hello-request message (type 0). This message has no additional payload except for the common
	 * payload described in SSLHandshakeMessage
	 */
	class SSLHelloRequestMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLHelloRequestMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		virtual ~SSLHelloRequestMessage()
		{}

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLServerKeyExchangeMessage
	 * Represents SSL/TLS server-key-exchange message (type 12). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as getting the server key exchange params as raw data (parsing of this may be added in the
	 * future)
	 */
	class SSLServerKeyExchangeMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLServerKeyExchangeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		~SSLServerKeyExchangeMessage()
		{}

		/**
		 * @return A pointer to the raw data of the server key exchange params. Currently this data can only returned as
		 * raw, parsing may be added in the future. Notice that if the message is spread over more than 1 packet in a
		 * way params doesn't exist in the first packet, nullptr will be returned
		 */
		uint8_t* getServerKeyExchangeParams() const;

		/**
		 * @return The size of the params field. Notice that if the message is spread over more than 1 packet in a way
		 * the ssl_tls_handshake_layer cannot be parsed from the packet, 0 will be returned. Also, if only part of the
		 * params exist in current packet (and the rest are on consequent packets), the size that will be returned is
		 * the size of the part that exists in the current packet (and not total size of params)
		 */
		size_t getServerKeyExchangeParamsLength() const;

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLClientKeyExchangeMessage
	 * Represents SSL/TLS client-key-exchange message (type 16). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as getting the server key exchange params as raw data (parsing of this may be added in the
	 * future)
	 */
	class SSLClientKeyExchangeMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLClientKeyExchangeMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		~SSLClientKeyExchangeMessage()
		{}

		/**
		 * @return A pointer to the raw data of the server key exchange params. Currently this data can only be returned
		 * as raw, parsing may be added in the future. Notice that if the message is spread over more than 1 packet in
		 * a way params doesn't exist in the first packet, nullptr will be returned
		 */
		uint8_t* getClientKeyExchangeParams() const;

		/**
		 * @return The size of the params field. Notice that if the message is spread over more than 1 packet in a way
		 * the ssl_tls_handshake_layer cannot be parsed from the packet, 0 will be returned. Also, if only part of the
		 * params exist in current packet (and the rest are on consequent packets), the size that will be returned is
		 * the size of the part that exists in the current packet (and not the total size of params)
		 */
		size_t getClientKeyExchangeParamsLength() const;

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLCertificateRequestMessage
	 * Represents SSL/TLS certificate-request message (type 13). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as retrieving client certificate types and authority data
	 */
	class SSLCertificateRequestMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLCertificateRequestMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container);

		~SSLCertificateRequestMessage()
		{}

		/**
		 * @return A reference to a vector containing all client certificate types exist in this message
		 */
		std::vector<SSLClientCertificateType>& getCertificateTypes();

		/**
		 * @return A pointer to the certificate authority data as raw data (byte array). Parsing of this data may be
		 * added in the future. Notice that if this message is spread over several packets in a way none of the
		 * certificate authority data exists in this packet, nullptr will be returned
		 */
		uint8_t* getCertificateAuthorityData() const;

		/**
		 * @return The length of certificate authority data returned by getCertificateAuthorityData(). Notice that if
		 * this message is spread over several packets in a way none of certificate authority data exists in the current
		 * packet, 0 will be returned. Also, if some of the data exists in the consequent packets, the length that will
		 * be returned is the length of data exists in the current packet only (and not the total length)
		 */
		size_t getCertificateAuthorityLength() const;

		// implement abstract methods

		std::string toString() const;

	private:
		std::vector<SSLClientCertificateType> m_ClientCertificateTypes;
	};

	/**
	 * @class SSLServerHelloDoneMessage
	 * Represents SSL/TLS server-hello-done message (type 14). This message has no additional payload except for the
	 * common payload described in SSLHandshakeMessage
	 */
	class SSLServerHelloDoneMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLServerHelloDoneMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		virtual ~SSLServerHelloDoneMessage()
		{}

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLCertificateVerifyMessage
	 * Represents SSL/TLS certificate-verify message (type 15). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as retrieving signed hash data as raw data (parsing may be added in the future)
	 * @todo This message type wasn't tested in unit-tests
	 */
	class SSLCertificateVerifyMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLCertificateVerifyMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		virtual ~SSLCertificateVerifyMessage()
		{}

		/**
		 * @return A pointer to the signed hash data as raw data (byte array). Parsing of this data may be added
		 * in the future. Notice that if this message is spread over several packets in a way none of the signed hash
		 * data exists in this packet, nullptr will be returned
		 */
		uint8_t* getSignedHash() const;

		/**
		 * @return The length of signed hash data returned by getSignedHash(). Notice that if this message is spread
		 * over several packets in a way none of this data exists in the current packet, 0 will be returned. Also, if
		 * some of the data exists in the consequent packets, the length that will be returned will be the length of
		 * data exists in the current packet only (and not the total length)
		 */
		size_t getSignedHashLength() const;

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLFinishedMessage
	 * Represents SSL/TLS finished message (type 20). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as retrieving signed hash data as raw data (parsing may be added in the future)
	 * @todo This message type wasn't tested in unit-tests
	 */
	class SSLFinishedMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLFinishedMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		virtual ~SSLFinishedMessage()
		{}

		/**
		 * @return A pointer to the signed hash data as raw data (byte array). Parsing of this data may be added
		 * in the future. Notice that if this message is spread over several packets in a way none of the signed hash
		 * data exists in this packet, nullptr will be returned
		 */
		uint8_t* getSignedHash() const;

		/**
		 * @return The length of signed hash data returned by getSignedHash(). Notice that if the message is spread over
		 * several packets in a way none of this data exists in the current packet, 0 will be returned. Also, if some of
		 * the data exists in the consequent packets, the length that will be returned will be the length of data exists
		 * in the current packet only (and not the total length)
		 */
		size_t getSignedHashLength() const;

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLNewSessionTicketMessage
	 * Represents SSL/TLS new-session-ticket message (type 4). Inherits from SSLHandshakeMessage and adds parsing
	 * functionality such as retrieving session ticket data as raw data (parsing may be added in the future)
	 */
	class SSLNewSessionTicketMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLNewSessionTicketMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		virtual ~SSLNewSessionTicketMessage()
		{}

		/**
		 * @return A pointer to the session ticket data as raw data (byte array). Parsing of this data may be added
		 * in the future. Notice that if this message is spread over several packets in a way none of the signed hash
		 * data exists in current packet, nullptr will be returned
		 */
		uint8_t* getSessionTicketData() const;

		/**
		 * @return The length of session ticket data returned by getSessionTicketData(). Notice that if this message is
		 * spread over several packets in a way none of this data exists in the current packet, 0 will be returned.
		 * Also, if some of the data exist in the consequent packets, the length that will be returned will be the
		 * length of the data existing in the current packet only (and not the total length)
		 */
		size_t getSessionTicketDataLength() const;

		// implement abstract methods

		std::string toString() const;
	};

	/**
	 * @class SSLUnknownMessage
	 * Represents an unknown type of message or an encrypted message that VanHooks can't determine its type. In
	 * these cases length can't always be determined from the message itself (especially if the message is encrypted),
	 * so the length of this message will always be the size counted from message start until the end of the layer
	 */
	class SSLUnknownMessage : public SSLHandshakeMessage
	{
	public:
		/**
		 * C'tor for this class. Currently only in use in SSLHandshakeMessage::createHandshakeMessage() and should be
		 * used by a user
		 * @param[in] data The message as raw data
		 * @param[in] dataLen Message raw data length in bytes
		 * @param[in] container The SSL handshake layer which shall contain this message
		 */
		SSLUnknownMessage(uint8_t* data, size_t dataLen, SSLHandshakeLayer* container)
		    : SSLHandshakeMessage(data, dataLen, container)
		{}

		virtual ~SSLUnknownMessage()
		{}

		// implement virtual and abstract methods

		/**
		 * @return Always ::SSL_HANDSHAKE_UNKNOWN (overridden from SSLHandshakeMessage)
		 */
		SSLHandshakeType getHandshakeType() const;

		/**
		 * @return The length of the data from message start until the end of the layer. Since it's an unknown type
		 * or an encrypted message the length parsed from the message can't be guaranteed to be the correct length.
		 * That's why the length returned is the size until the end of the layer
		 */
		size_t getMessageLength() const;

		std::string toString() const;
	};

	template <class TExtension> TExtension* SSLClientHelloMessage::getExtensionOfType() const
	{
		size_t vecSize = m_ExtensionList.size();
		for (size_t i = 0; i < vecSize; i++)
		{
			SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
			if (dynamic_cast<TExtension*>(curElem) != nullptr)
				return (TExtension*)curElem;
		}

		return nullptr;
	}

	template <class TExtension> TExtension* SSLServerHelloMessage::getExtensionOfType() const
	{
		size_t vecSize = m_ExtensionList.size();
		for (size_t i = 0; i < vecSize; i++)
		{
			SSLExtension* curElem = const_cast<SSLExtension*>(m_ExtensionList.at(i));
			if (dynamic_cast<TExtension*>(curElem) != nullptr)
				return (TExtension*)curElem;
		}

		return nullptr;
	}

}  // namespace vanhooks::net
// ---- end SSLHandshake.h ----

// ---- begin SSLLayer.h ----
/**
 * @file
 * This file as well as SSLCommon.h and SSLHandshake.h provide structures that represent SSL/TLS protocol.
 * Main features:
 * - All common SSL/TLS version are supported from SSL 3.0 to TLS 1.3
 * - All SSL/TLS message types are supported (at least the message types that are not encrypted)
 * - More than 300 cipher-suites are supported
 * - Only parsing capabilities exist, editing and creation of messages are not supported
 * - X509 certificate parsing is not supported
 *
 * <BR><BR>
 *
 * __SSL Records:__   <BR>
 *
 * The SSL/TLS protocol has 4 types of records:
 * - Handshake record type
 * - Change cipher spec record type
 * - Alert record type
 * - Application data record type
 *
 * Each record type corresponds to a layer class, and these classes inherit from one base class which is vanhooks::net::SSLLayer.
 * The vanhooks::net::SSLLayer is an abstract class which cannot be instantiated. Only its 4 derived classes can be instantiated.
 * This means you'll never see a layer of type vanhooks::net::SSLLayer, you'll only see the type of the derived classes.
 * A basic class diagram looks like this:
  @verbatim
                                 +----------------------------+
                             +---|     SSLHandshakeLayer      | ===> Handshake record type
                             |   +----------------------------+
                             |
                             |   +----------------------------+
                             +---|  SSLChangeCipherSpecLayer  | ===> Change cipher spec record type
                             |   +----------------------------+
                             |
  +------------+             |   +----------------------------+
  |  SSLLayer  |-------------+---|      SSLAlertLayer         | ===> Alert record type
  | (abstract) |             |   +----------------------------+
  +------------+             |
                             |   +----------------------------+
                             +---|   SSLApplicationDataLayer  | ===> Application data record type
                                 +----------------------------+

  @endverbatim
 *
 * A single packet may include several SSL/TLS records, meaning several layer instances of these types, for example:
 *
  @verbatim

            +--------------------------+
            |          EthLayer        |
            +--------------------------+
            |          IPv4Layer       |
            +--------------------------+
            |          TcpLayer        |
            +--------------------------+
            |    SSLHandshakeLayer     | \
            +--------------------------+  \
            | SSLChangeCipherSpecLayer | -------- 3 SSL/TLS records in the same packet!
            +--------------------------+  /
            |    SSLHandshakeLayer     | /
            +--------------------------+

  @endverbatim
 *
 * <BR><BR>
 *
 * __SSL/TLS Handshake records:__    <BR>
 *
 * The SSL/TLS handshake records are the most complex ones. These type of records encapsulate all messages between
 * client and server during SSL/TLS connection establishment. To accomplish that a SSL/TLS handshake record holds
 * zero or more handshake messages (usually it holds 1 message). These messages form the handshake negotiation between
 * the client and the server. There are several types of handshake messages. Some of the are sent from client to server
 * and some from server to client. VanHooks supports 11 of these types (definitely the most common ones). For each
 * message there is a designated class which parses the message and exposes its attributes in an easy-to-use manner.
 * Here are the list of supported messages:
 * - Client-hello
 * - Server-hello
 * - Certificate
 * - Hello-request
 * - Server-key-exchange
 * - Client-key-exchange
 * - Certificate-request
 * - Server-hello-done
 * - Certificate-verify
 * - Finished
 * - New-session-ticket
 *
 * All handshake messages classes inherit from a base abstract class: vanhooks::net::SSLHandshakeMessage which cannot be
 * instantiated.
 * Also, all of them reside in SSLHandshake.h. Following is a simple diagram of these classes:
 *
 @verbatim

                                          SSLHandshakeMessage
                                             |
 +-------------------------------+           |--- SSLClientHelloMessage        ==> Client-hello message
 |       SSLHandshakeLayer       |           |
 +-------------------------------+           |--- SSLServerHelloMessage        ==> Server-hello message
 | -List of SSLHandshakeMessage  |           |
 |     Message1                  |           |---SSLCertificateMessage         ==> Certificate message
 |     Message2                  |           |
 |     ...                       |           |---SSLHelloRequestMessage        ==> Hello-request message
 |                               |           |
 +-------------------------------+           |---SSLServerKeyExchangeMessage   ==> Server-key-exchange message
                                             |
                                             |---SSLClientKeyExchangeMessage   ==> Client-key-exchange message
                                             |
                                             |---SSLCertificateRequestMessage  ==> Certificate-request message
                                             |
                                             |---SSLServerHelloDoneMessage     ==> Server-hello-done message
                                             |
                                             |---SSLCertificateVerifyMessage   ==> Certificate-verify message
                                             |
                                             |---SSLFinishedMessage            ==> Finished message
                                             |
                                             |---SSLNewSessionTicketMessage    ==> New-session-ticket message

 @endverbatim
 *
 * In addition, for all handshake messages which aren't supported in VanHooks or for encrypted handshake messages
 * There is another class: vanhooks::net::SSLUnknownMessage
 *
 * <BR><BR>
 *
 * __Cipher suites:__    <BR>
 *
 * Cipher suites are named combinations of authentication, encryption, message authentication code (MAC) and key
 * exchange algorithms used to negotiate the security settings for a network connection using SSL/TLS.
 * There are many known cipher-suites. VanHooks support above 300 of them, according to this list:
 * http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 * There is a designated class in VanHooks called vanhooks::net::SSLCipherSuite which represents the cipher-suites and
 * provides access to their attributes. Then there is a static instance of this class for each one of the supported
 * cipher-suites.
 * This means there are 300+ static instances of vanhooks::net::SSLCipherSuite representing the different cipher suites. The user
 * can access them through static methods in vanhooks::net::SSLCipherSuite or from client-hello and server-hello messages where
 * they appear.
 *
 * <BR><BR>
 *
 * __SSL/TLS extensions:__    <BR>
 *
 * SSL/TLS handshake messages, specifically client-hello and server-hello usually include extensions. There are various
 * types of extensions - some are more broadly used, some are less. In VanHooks there is a base class for all
 * extensions: vanhooks::net::SSLExtension. This class is instantiable and represents a generic extension, which means extension
 * data isn't parsed and given to the user as raw data. Currently there are only two extension that are fully parsed
 * which are server-name-indication (vanhooks::net::SSLServerNameIndicationExtension) and SupportedVersions
 * (vanhooks::net::SSLSupportedVersionsExtension).
 * Both inherit from vanhooks::net::SSLExtension and add additional parsing relevant for the specific extension.
 * All other extensions aren't parsed and are represented by instance of vanhooks::net::SSLExtension.
 * Access to extensions is done through the handshake messages classes, specifically vanhooks::net::SSLClientHelloMessage and
 * vanhooks::net::SSLServerHelloMessage
 */

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @class SSLLayer
	 * The base class for the 4 record type classes. Each record type is represented as a layer. See SSLLayer.h for
	 * detailed explanation of the TLS/SSL protocol support in VanHooks.
	 * This class provides the common functionality used by all record types and also contains static methods for
	 * identifying an creating SSL/TLS record type layers
	 */
	class SSLLayer : public Layer
	{
	public:
		/**
		 * A static method that checks whether the port is considered as SSL/TLS
		 * @param[in] port The port number to be checked
		 */
		static inline bool isSSLPort(uint16_t port);

		/**
		 * A static methods that gets raw data of a layer and checks whether this data is a SSL/TLS record or not. This
		 * check is done using the source/dest port and matching of a legal record type in the raw data. The list of
		 * ports identified as SSL/TLS is hard-coded and includes the following ports:
		 * - Port 443 [HTTPS]
		 * - Port 261 [NSIIOPS]
		 * - Port 448 [DDM-SSL]
		 * - Port 563 [NNTPS]
		 * - Port 614 [SSHELL]
		 * - Port 465 [SMTPS]
		 * - Port 636 [LDAPS]
		 * - Port 989 [FTPS - data]
		 * - Port 990 [FTPS - control]
		 * - Port 992 [Telnet over TLS/SSL]
		 * - Port 993 [IMAPS]
		 * - Port 994 [IRCS]
		 * - Port 995 [POP3S]
		 * @param[in] srcPort The source port of the packet that contains the raw data. Source port (or dest port) are a
		 * criteria to identify SSL/TLS packets
		 * @param[in] dstPort The dest port of the packet that contains the raw data. Dest port (or source port) are a
		 * criteria to identify SSL/TLS packets
		 * @param[in] data The data to check
		 * @param[in] dataLen Length (in bytes) of the data
		 * @param[in] ignorePorts SSL/TLS ports are only relevant for parsing the first SSL/TLS message, but are not
		 * relevant for parsing subsequent messages. This parameter can be set to "true" to skip SSL/TLS ports check.
		 * This is an optional parameter and its default is "false"
		 */
		static bool IsSSLMessage(uint16_t srcPort, uint16_t dstPort, uint8_t* data, size_t dataLen,
		                         bool ignorePorts = false);

		/**
		 * A static method that creates SSL/TLS layers by raw data. This method parses the raw data, finds if and which
		 * SSL/TLS record it is and creates the corresponding record layer. It's the responsibility of the user to free
		 * the created object when done using it
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return A pointer to the newly created record layer. If no SSL/TLS record could be identified from the raw
		 * data nullptr is returned
		 */
		static SSLLayer* createSSLMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * Get a pointer to the record header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the @ref ssl_tls_record_layer
		 */
		ssl_tls_record_layer* getRecordLayer() const
		{
			return (ssl_tls_record_layer*)m_Data;
		}

		/**
		 * @return The SSL/TLS version used in this record (parsed from the record)
		 */
		SSLVersion getRecordVersion() const;

		/**
		 * @return The SSL/TLS record type as parsed from the record
		 */
		SSLRecordType getRecordType() const;

		// implement abstract methods

		/**
		 * @return The record size as extracted from the record data (in ssl_tls_record_layer#length)
		 */
		size_t getHeaderLen() const;

		/**
		 * Several SSL/TLS records can reside in a single packets. So this method checks the remaining data and if it's
		 * identified as SSL/TLS it creates another SSL/TLS record layer as the next layer
		 */
		void parseNextLayer();

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelPresentationLayer;
		}

	protected:
		SSLLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : Layer(data, dataLen, prevLayer, packet, SSL)
		{}

	};  // class SSLLayer

	// The graph below will break the code formatting, so it's disabled.
	// clang-format off
	/**
	 * @class SSLHandshakeLayer
	 * Represents SSL/TLS handshake layer. This layer may contain one or more handshake messages (all of them inherit
	 * from the base class SSLHandshakeMessage) which are the SSL/TLS handshake message sent between a client and a
	 * server until they establish a secure connection (e.g client-hello, server-hello, certificate,
	 * client-key-exchange, server-key-exchange, etc.).
	 * Usually this layer will contain just one message (as the first example below
	 * demonstrates). But there are cases a layer may contain more than 1 message. To better explain this layer
	 * structure. We'll use 2 examples. The first will be client-hello message. The layer structure will look like this:
	 @verbatim

	         |------------------- SSLHandshakeLayer ----------------------|
	         +----------------------+-------------------------------------+
	         | ssl_tls_record_layer |       SSLClientHelloMessage         |
	         |        struct        |                                     |
	         +----------------------+-------------------------------------+
	          /     |       \               |          \         \      \
	         /    version    \      |   handshake       \         \      \
	        /     TLS1_0      \            type          \         \     rest of
	     type                  \    | SSL_CLIENT_HELLO    \         \    message fields...
	 SSL_HANDSHAKE           length                   handshake      \
	     (22)                 xxx   |                  version      message
	                                                   TLS1_2      length
	                                |                                yyy
	 @endverbatim

	 * Second example is a multiple-message handshake layer comprises of server-hello, certificate and
	 * server-key-exchange messages:

	 @verbatim

	         |---------------------------------------------- SSLHandshakeLayer -----------------------------------------------------|
	         +----------------------+-------------------------------------+---------------------------+-----------------------------+
	         | ssl_tls_record_layer |       SSLServerHelloMessage         |   SSLCertificateMessage   | SSLServerKeyExchangeMessage |
	         |        struct        |                                     |                           |                             |
	         +----------------------+-------------------------------------+---------------------------+-----------------------------+
	          /     |       \               |          \         \               |           \               |            \
	         /    version    \      |   handshake       \        rest of  |      |          rest      |      |            rest
	        /     TLS1_0      \            type          \       message      handshake   of fields...   handshake    of fields...
	     type                  \    | SSL_SERVER_HELLO    \      fields...|     type                  |     type
	 SSL_HANDSHAKE           length                   handshake             SSL_CERTIFICATE             SSL_SERVER_KEY_EXCHANGE
	     (22)                 xxx   |               version,length        |                           |
	 @endverbatim
	 */
	// clang-format on
	class SSLHandshakeLayer : public SSLLayer
	{
	public:
		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLHandshakeLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * @return The number of messages in this layer instance
		 */
		size_t getHandshakeMessagesCount() const
		{
			return m_MessageList.size();
		}

		/**
		 * Get a pointer to an handshake message by index. The message are numbered according to their order of
		 * appearance in the layer. If index is out of bounds (less than 0 or larger than total amount of message)
		 * nullptr will be returned
		 * @param[in] index The index of the message to return
		 * @return The pointer to the message object or nullptr if index is out of bounds
		 */
		SSLHandshakeMessage* getHandshakeMessageAt(int index) const;

		/**
		 * A templated method to get a message of a certain type. If no message of such type is found, nullptr is
		 * returned
		 * @return A pointer to the message of the requested type, nullptr if not found
		 */
		template <class THandshakeMessage> THandshakeMessage* getHandshakeMessageOfType() const;

		/**
		 * A templated method to get the first message of a certain type, starting to search from a certain message.
		 * For example: if the layer looks like: HelloRequest(1) -> HelloRequest(2)
		 * and the user put HelloRequest(1) as a parameter and wishes to search for an HelloRequest message, the
		 * HelloRequest(2) will be returned.<BR>
		 * If no layer of such type is found, nullptr is returned
		 * @param[in] after A pointer to the message to start search from
		 * @return A pointer to the message of the requested type, nullptr if not found
		 */
		template <class THandshakeMessage>
		THandshakeMessage* getNextHandshakeMessageOfType(const SSLHandshakeMessage* after) const;

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields()
		{}

	private:
		PointerVector<SSLHandshakeMessage> m_MessageList;
	};  // class SSLHandshakeLayer

	/**
	 * @class SSLChangeCipherSpecLayer
	 * Represents SSL/TLS change-cipher-spec layer. This layer has no additional fields besides common fields described
	 * in SSLLayer
	 */
	class SSLChangeCipherSpecLayer : public SSLLayer
	{
	public:
		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLChangeCipherSpecLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSLLayer(data, dataLen, prevLayer, packet)
		{}

		~SSLChangeCipherSpecLayer()
		{}

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields()
		{}
	};  // class SSLChangeCipherSpecLayer

	/**
	 * @class SSLAlertLayer
	 * Represents SSL/TLS alert layer. Inherits from SSLLayer and adds parsing functionality such as retrieving the
	 * alert level and description
	 */
	class SSLAlertLayer : public SSLLayer
	{
	public:
		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLAlertLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSLLayer(data, dataLen, prevLayer, packet)
		{}

		~SSLAlertLayer()
		{}

		/**
		 * @return SSL/TLS alert level. Will return ::SSL_ALERT_LEVEL_ENCRYPTED if alert is encrypted
		 */
		SSLAlertLevel getAlertLevel() const;

		/**
		 * @return SSL/TLS alert description. Will return ::SSL_ALERT_ENCRYPTED if alert is encrypted
		 */
		SSLAlertDescription getAlertDescription();

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields()
		{}
	};  // class SSLAlertLayer

	/**
	 * @class SSLApplicationDataLayer
	 * Represents SSL/TLS application data layer. This message contains the encrypted data transferred from client to
	 * server and vice-versa after the SSL/TLS handshake was completed successfully
	 */
	class SSLApplicationDataLayer : public SSLLayer
	{
	public:
		/**
		 * C'tor for this class that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		SSLApplicationDataLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : SSLLayer(data, dataLen, prevLayer, packet)
		{}

		~SSLApplicationDataLayer()
		{}

		/**
		 * @return A pointer to the encrypted data. This data can be decrypted only if you have the symmetric key
		 * that was agreed between the client and the server during SSL/TLS handshake process
		 */
		uint8_t* getEncryptedData() const;

		/**
		 * @return The length in bytes of the encrypted data returned in getEncryptedData()
		 */
		size_t getEncryptedDataLen() const;

		// implement abstract methods

		std::string toString() const;

		/**
		 * There are no calculated fields for this layer
		 */
		void computeCalculateFields()
		{}
	};  // class SSLApplicationDataLayer

	template <class THandshakeMessage> THandshakeMessage* SSLHandshakeLayer::getHandshakeMessageOfType() const
	{
		size_t vecSize = m_MessageList.size();
		for (size_t i = 0; i < vecSize; i++)
		{
			SSLHandshakeMessage* curElem = const_cast<SSLHandshakeMessage*>(m_MessageList.at(i));
			if (dynamic_cast<THandshakeMessage*>(curElem) != nullptr)
				return (THandshakeMessage*)curElem;
		}

		// element not found
		return nullptr;
	}  // getHandshakeMessageOfType

	template <class THandshakeMessage>
	THandshakeMessage* SSLHandshakeLayer::getNextHandshakeMessageOfType(const SSLHandshakeMessage* after) const
	{
		size_t vecSize = m_MessageList.size();
		size_t afterIndex;

		// find the index of "after"
		for (afterIndex = 0; afterIndex < vecSize; afterIndex++)
		{
			SSLHandshakeMessage* curElem = const_cast<SSLHandshakeMessage*>(m_MessageList.at(afterIndex));
			if (curElem == after)
				break;
		}

		// "after" not found
		if (afterIndex == vecSize)
			return nullptr;

		for (size_t i = afterIndex + 1; i < vecSize; i++)
		{
			SSLHandshakeMessage* curElem = const_cast<SSLHandshakeMessage*>(m_MessageList.at(i));
			if (dynamic_cast<THandshakeMessage*>(curElem) != nullptr)
				return (THandshakeMessage*)curElem;
		}

		// element not found
		return nullptr;
	}  // getNextHandshakeMessageOfType

	// implementation of inline methods

	bool SSLLayer::isSSLPort(uint16_t port)
	{
		if (port == 443)  // HTTPS, this is likely case
			return true;

		switch (port)
		{
		case 261:  // NSIIOPS
		case 448:  // DDM-SSL
		case 465:  // SMTPS
		case 563:  // NNTPS
		case 614:  // SSHELL
		case 636:  // LDAPS
		case 989:  // FTPS - data
		case 990:  // FTPS - control
		case 992:  // Telnet over TLS/SSL
		case 993:  // IMAPS
		case 994:  // IRCS
		case 995:  // POP3S
			return true;
		default:
			return false;
		}
	}  // isSSLPort

}  // namespace vanhooks::net
// ---- end SSLLayer.h ----

// ---- begin LdapLayer.h ----
#include <ostream>
#include <string>
#include <functional>

/// @file

/**
 * @namespace vanhooks::net
 * @brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * @class LdapOperationType
	 * @brief An enum wrapper class for LDAP operation types
	 */
	class LdapOperationType
	{
	public:
		/**
		 * Define enum types and the corresponding int values
		 */
		enum Value : uint8_t
		{
			/// Bind Request
			BindRequest = 0,
			/// Bind Response
			BindResponse = 1,
			/// Unbind Request
			UnbindRequest = 2,
			/// Search Request
			SearchRequest = 3,
			/// Search Result Entry
			SearchResultEntry = 4,
			/// Search Result Done
			SearchResultDone = 5,
			/// Modify Request
			ModifyRequest = 6,
			/// Modify Response
			ModifyResponse = 7,
			/// Add Request
			AddRequest = 8,
			/// Add Response
			AddResponse = 9,
			/// Delete Request
			DeleteRequest = 10,
			/// Delete Response
			DeleteResponse = 11,
			/// Modify DN (Distinguished Name) Request
			ModifyDNRequest = 12,
			/// Modify DN (Distinguished Name) Response
			ModifyDNResponse = 13,
			/// Compare Request
			CompareRequest = 14,
			/// Compare Response
			CompareResponse = 15,
			/// Abandon Request
			AbandonRequest = 16,
			/// Search Result Reference
			SearchResultReference = 19,
			/// Extended Request
			ExtendedRequest = 23,
			/// Extended Response
			ExtendedResponse = 24,
			/// Intermediate Response
			IntermediateResponse = 25,
			/// Unknown operation type
			Unknown = 255
		};

		LdapOperationType() = default;

		// cppcheck-suppress noExplicitConstructor
		/**
		 * Construct LdapOperationType from Value enum
		 * @param[in] value the opetation type enum value
		 */
		constexpr LdapOperationType(Value value) : m_Value(value)
		{}

		/**
		 * @return A string representation of the operation type
		 */
		std::string toString() const;

		/**
		 * A static method that creates LdapOperationType from an integer value
		 * @param[in] value The operation type integer value
		 * @return The operation type that corresponds to the integer value. If the integer value
		 * doesn't corresponds to any operation type, LdapOperationType::Unknown is returned
		 */
		static LdapOperationType fromUintValue(uint8_t value);

		// Allow switch and comparisons.
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(LdapOperationType)
		explicit operator bool() const = delete;

	private:
		Value m_Value = LdapOperationType::Unknown;
	};

	/**
	 * @class LdapResultCode
	 * @brief An enum wrapper class for LDAP result codes
	 */
	class LdapResultCode
	{
	public:
		/**
		 * Define enum types and the corresponding int values
		 */
		enum Value : uint8_t
		{
			/**
			 * Indicates that the associated operation completed successfully
			 */
			Success = 0,
			/**
			 * Indicates that there was a problem with the client’s use of the LDAP protocol
			 */
			OperationsError = 1,
			/**
			 * Indicates that there was a problem with the client’s use of the LDAP protocol
			 */
			ProtocolError = 2,
			/**
			 * Indicates that the associated operation failed because it hadn’t completed by the time
			 * a maximum processing time limit had been reached
			 */
			TimeLimitExceeded = 3,
			/**
			 * Indicates that the associated search operation failed because the server has determined
			 * that the number of entries that would be returned in response to the search would exceed
			 * the upper bound for that operation
			 */
			SizeLimitExceeded = 4,
			/**
			 * Indicates that the associated compare request targeted an entry that exists and that contains
			 * the targeted attribute, but does not have any value that matches the provided assertion value
			 */
			CompareFalse = 5,
			/**
			 * Indicates that the associated compare request targeted an entry that exists and that contains
			 * the targeted attribute with a value that matches the provided assertion value
			 */
			CompareTrue = 6,
			/**
			 * Indicates that the associated bind operation failed because the client attempted to authenticate
			 * with a mechanism that the server does not support or that it does not allow the client to use
			 */
			AuthMethodNotSupported = 7,
			/**
			 * Indicates that the server requires the client to authenticate with a stronger form of authentication
			 */
			StrongerAuthRequired = 8,
			/**
			 * Indicates that the request cannot be processed exactly as issued, but that it might succeed
			 * if re-issued to a different server, or is updated to target a different location in the DIT
			 */
			Referral = 10,
			/**
			 * Indicates that some administrative limit within the server was exceeded while processing the request
			 */
			AdminLimitExceeded = 11,
			/**
			 * Indicates that the request includes a control with a criticality of true,
			 * but that control could not be honored for some reason
			 */
			UnavailableCriticalExtension = 12,
			/**
			 * Indicates that the server is only willing to process the requested operation if it is received
			 * over a secure connection that does not allow an eavesdropper to decipher or alter the contents
			 * of the request or response
			 */
			ConfidentialityRequired = 13,
			/**
			 * Indicates that the server has completed a portion of the processing for the provided SASL
			 * bind request, but that it needs additional information from the client to complete the authentication
			 */
			SaslBindInProgress = 14,
			/**
			 * Indicates that the request targeted an attribute that does not exist in the specified entry
			 */
			NoSuchAttribute = 16,
			/**
			 * Indicates that the request attempted to provide one or more values for an attribute type
			 * that is not defined in the server schema
			 */
			UndefinedAttributeType = 17,
			/**
			 * Indicates that the search request tried to perform some type of matching that is not
			 * supported for the target attribute type
			 */
			InappropriateMatching = 18,
			/**
			 * Indicates that the requested operation would have resulted in an entry that violates
			 * some constraint defined within the server
			 */
			ConstraintViolation = 19,
			/**
			 * Indicates that the requested operation would have resulted in an attribute in which
			 * the same value appeared more than once
			 */
			AttributeOrValueExists = 20,
			/**
			 * Indicates that the requested add or modify operation would have resulted in an entry
			 * that had at least one attribute value that does not conform to the constraints of the
			 * associated attribute syntax
			 */
			InvalidAttributeSyntax = 21,
			/**
			 * Indicates that the requested operation targeted an entry that does not exist within the DIT
			 */
			NoSuchObject = 32,
			/**
			 * Indicates that a problem occurred while attempting to dereference an alias during search processing
			 */
			AliasProblem = 33,
			/**
			 * Indicates that the request included a malformed entry DN
			 */
			InvalidDNSyntax = 34,
			/**
			 * Indicates that the server encountered an alias while processing the request and that there
			 * was some problem related to that alias
			 */
			AliasDereferencingProblem = 36,
			/**
			 * Indicates that the client attempted to bind in an inappropriate manner that is inappropriate
			 * for the target account
			 */
			InappropriateAuthentication = 48,
			/**
			 * Indicates that the client attempted to bind with a set of credentials that cannot
			 * be used to authenticate
			 */
			InvalidCredentials = 49,
			/**
			 * Indicates that the client requested an operation for which it does not have the necessary
			 * access control permissions
			 */
			InsufficientAccessRights = 50,
			/**
			 * Indicates that the requested operation cannot be processed because the server is currently too busy
			 */
			Busy = 51,
			/**
			 * Indicates that the server is currently not available to process the requested operation
			 */
			Unavailable = 52,
			/**
			 * Indicates that the server is not willing to process the requested operation for some reason
			 */
			UnwillingToPerform = 53,
			/**
			 * Indicates that the server detected some kind of circular reference in the course
			 * of processing an operation
			 */
			LoopDetect = 54,
			/**
			 * Indicates that the requested add or modify DN operation would have resulted in an entry
			 * that violates some naming constraint within the server
			 */
			NamingViolation = 64,
			/**
			 * Indicates that the requested operation would have resulted in an entry that has
			 * an inappropriate set of object classes, or whose attributes violate the constraints
			 * associated with its set of object classes
			 */
			ObjectClassViolation = 65,
			/**
			 * Indicates that the requested operation is only supported for leaf entries,
			 * but the targeted entry has one or more subordinates
			 */
			NotAllowedOnNonLeaf = 66,
			/**
			 * Indicates that the requested modify operation would have resulted in an entry that
			 * does not include all of the attributes used in its RDN
			 */
			NotAllowedOnRDN = 67,
			/**
			 * Indicates that the requested operation would have resulted in an entry with the same
			 * DN as an entry that already exists in the server
			 */
			EntryAlreadyExists = 68,
			/**
			 * Indicates that the requested modify operation would have altered the target entry’s
			 * set of object classes in a way that is not supported
			 */
			ObjectClassModsProhibited = 69,
			/**
			 * Indicates that the requested operation would have required manipulating information
			 * in multiple servers in a way that is not supported
			 */
			AffectsMultipleDSAs = 71,
			/**
			 * Used when a problem occurs for which none of the other result codes is more appropriate
			 */
			Other = 80,
			/**
			 * Unknown result code
			 */
			Unknown = 255
		};

		LdapResultCode() = default;

		// cppcheck-suppress noExplicitConstructor
		/**
		 * Construct LdapResultCode from Value enum
		 * @param[in] value the result code enum value
		 */
		constexpr LdapResultCode(Value value) : m_Value(value)
		{}

		/**
		 * @return A string representation of the result code
		 */
		std::string toString() const;

		/**
		 * A static method that creates LdapResultCode from an integer value
		 * @param[in] value The result code integer value
		 * @return The result code that corresponds to the integer value. If the integer value
		 * doesn't corresponds to any operation type, LdapResultCode::Unknown is returned
		 */
		static LdapResultCode fromUintValue(uint8_t value);

		// Allow switch and comparisons
		constexpr operator Value() const
		{
			return m_Value;
		}

		// Prevent usage: if(LdapResultCode)
		explicit operator bool() const = delete;

	private:
		Value m_Value = LdapResultCode::Unknown;
	};

	/**
	 * @struct LdapControl
	 * A struct that represents an LDAP Control
	 */
	struct LdapControl
	{
		/// LDAP control type
		std::string controlType;
		/// LDAP control value
		std::string controlValue;

		/**
		 * Equality operator overload for this struct
		 * @param[in] other The value to compare with
		 * @return True if both values are equal, false otherwise
		 */
		bool operator==(const LdapControl& other) const
		{
			return controlType == other.controlType && controlValue == other.controlValue;
		}
	};

	/**
	 * @struct LdapAttribute
	 * A struct that represents an LDAP attribute
	 */
	struct LdapAttribute
	{
		/// Attribute description
		std::string type;
		/// A list of attribute values (zero or more)
		std::vector<std::string> values;

		/**
		 * Equality operator overload for this struct
		 * @param[in] other The value to compare with
		 * @return True if both values are equal, false otherwise
		 */
		bool operator==(const LdapAttribute& other) const
		{
			return type == other.type && values == other.values;
		}
	};

	/**
	 * @class LdapLayer
	 * Represents an LDAP message
	 */
	class LdapLayer : public Layer
	{
	public:
		/**
		 * A constructor to create a new LDAP message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] operationType The LDAP operation type
		 * @param[in] messageRecords A vector of ASN.1 records that comprise the LDAP message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapLayer(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords,
		          const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		~LdapLayer()
		{}

		/**
		 * @return The root ASN.1 record of the LDAP message. All of the message data will be under this record.
		 * If the Root ASN.1 record is malformed, an exception is thrown
		 */
		Asn1SequenceRecord* getRootAsn1Record() const;

		/**
		 * @return The ASN.1 record of the specific LDAP operation in this LDAP message. Each operation has a specific
		 * structure. If the Operation ASN.1 record is malformed, an exception is thrown
		 */
		Asn1ConstructedRecord* getLdapOperationAsn1Record() const;

		/**
		 * @return The LDAP message ID. If the ASN.1 record is malformed, an exception is thrown
		 */
		uint16_t getMessageID() const;

		/**
		 * @return A vector of LDAP controls in this message. If the message contains no controls then an empty
		 * vector is returned. If the Controls ASN.1 record is malformed, an exception is thrown
		 */
		std::vector<LdapControl> getControls() const;

		/**
		 * @return The LDAP operation of this message. If the Operation ASN.1 record is malformed, an exception is
		 * thrown
		 */
		virtual LdapOperationType getLdapOperationType() const;

		/**
		 * Most getter methods in this class throw an exception if the corresponding ASN.1 record is invalid.
		 * This is a wrapper method that allows calling these getters without adding a `try...catch` clause.
		 * It accepts the getter method and an out variable. It tries to call the getter and if no exception
		 * is thrown, the out variable will contain the result.
		 *
		 * Here is an example:
		 * @code
		 * uint16_t messageId;
		 * ldapLayer->tryGet(&vanhooks::net::LdapLayer::getMessageID, messageId));
		 * @endcode
		 *
		 * We call getMessageID(), if no exception is thrown the variable messageId will hold the result
		 *
		 * @tparam Method The class method type
		 * @tparam ResultType The expected result type (for example: uint8_t, std::string, etc.)
		 * @param[in] method The class method to call
		 * @param[out] result An outvariable to contain the result if no exception is thrown
		 * @return True if no exception was thrown or false otherwise
		 */
		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

		/**
		 * A static method that checks whether a source or dest port match those associated with the LDAP protocol
		 * @param[in] port The port number to check
		 * @return True if this is an LDAP port, false otherwise
		 */
		static bool isLdapPort(uint16_t port)
		{
			return port == 389;
		}

		/**
		 * A static message to parse an LDAP message from raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 * @return An instance of LdapLayer if this is indeed an LDAP message, nullptr otherwise
		 */
		static LdapLayer* parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		// implement abstract methods

		/**
		 * Tries to identify more LDAP messages in this packet if exist
		 */
		void parseNextLayer() override;

		/**
		 * @return The size of the LDAP message
		 */
		size_t getHeaderLen() const override
		{
			return m_Asn1Record->getTotalLength();
		}

		void computeCalculateFields() override
		{}

		OsiModelLayer getOsiModelLayer() const override
		{
			return OsiModelApplicationLayer;
		}

		std::string toString() const override;

	protected:
		std::unique_ptr<Asn1Record> m_Asn1Record;

		LdapLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		          Packet* packet);
		LdapLayer() = default;
		void init(uint16_t messageId, LdapOperationType operationType, const std::vector<Asn1Record*>& messageRecords,
		          const std::vector<LdapControl>& controls);
		virtual std::string getExtendedInfoString() const
		{
			return "";
		}

		static constexpr int messageIdIndex = 0;
		static constexpr int operationTypeIndex = 1;
		static constexpr int controlsIndex = 2;

		static constexpr int controlTypeIndex = 0;
		static constexpr int controlValueIndex = 1;

		template <typename LdapClass, typename Method, typename ResultType>
		bool internalTryGet(LdapClass* thisPtr, Method method, ResultType& result)
		{
			try
			{
				result = std::mem_fn(method)(thisPtr);
				return true;
			}
			catch (...)
			{
				return false;
			}
		}
	};

	/**
	 * @class LdapResponseLayer
	 * An abstract class for representing an LDAP response message. It's the parent class
	 * for all response message layers
	 */
	class LdapResponseLayer : public LdapLayer
	{
	public:
		/**
		 * @return LDAP result code
		 */
		LdapResultCode getResultCode() const;

		/**
		 * @return An optional distinguished name (DN) that may be included in the response to a request
		 * targeting an entry that does not exist
		 */
		std::string getMatchedDN() const;

		/**
		 * @return An optional string that can provide additional information about the processing that
		 * was performed
		 */
		std::string getDiagnosticMessage() const;

		/**
		 * @return An optional list of one or more URIs that the client may use to re-try the operation
		 * somewhere else. If referral doesn't exist on the message, and empty vector is returned
		 */
		std::vector<std::string> getReferral() const;

	protected:
		static constexpr int resultCodeIndex = 0;
		static constexpr int matchedDNIndex = 1;
		static constexpr int diagnotsticsMessageIndex = 2;
		static constexpr int referralIndex = 3;

		static constexpr uint8_t referralTagType = 3;

		LdapResponseLayer() = default;
		LdapResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                  Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}

		LdapResponseLayer(uint16_t messageId, LdapOperationType operationType, LdapResultCode resultCode,
		                  const std::string& matchedDN, const std::string& diagnosticMessage,
		                  const std::vector<std::string>& referral = std::vector<std::string>(),
		                  const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		void init(uint16_t messageId, LdapOperationType operationType, LdapResultCode resultCode,
		          const std::string& matchedDN, const std::string& diagnosticMessage,
		          const std::vector<std::string>& referral = std::vector<std::string>(),
		          const std::vector<Asn1Record*>& additionalRecords = std::vector<Asn1Record*>(),
		          const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		std::string getExtendedInfoString() const override;
	};

	/**
	 * @class LdapBindRequestLayer
	 * Represents LDAP bind request operation
	 */
	class LdapBindRequestLayer : public LdapLayer
	{
	public:
		/**
		 * An enum to represent the bind request authentication type
		 */
		enum class AuthenticationType : uint8_t
		{
			/// Simple authentication
			Simple = 0,
			/// SASL authentication
			Sasl = 3,
			/// Unknown / not application authentication type
			NotApplicable = 255
		};

		/**
		 * @struct SaslAuthentication
		 * A struct to represent SASL authentication
		 */
		struct SaslAuthentication
		{
			/// The SASL mechanism
			std::string mechanism;
			/// Encoded SASL credentials
			std::vector<uint8_t> credentials;

			/**
			 * Equality operator overload for this struct
			 * @param[in] other The value to compare with
			 * @return True if both values are equal, false otherwise
			 */
			bool operator==(const SaslAuthentication& other) const
			{
				return mechanism == other.mechanism && credentials == other.credentials;
			}

			/**
			 * Inequality operator overload for this struct
			 * @param[in] other The value to compare with
			 * @return False if both values are equal, true otherwise
			 */
			bool operator!=(const SaslAuthentication& other) const
			{
				return !operator==(other);
			}
		};

		/**
		 * A constructor to create a new LDAP bind request message with simple authentication
		 * @param[in] messageId The LDAP message ID
		 * @param[in] version The LDAP protocol version that the client wants to use
		 * @param[in] name The DN of the user to authenticate
		 * @param[in] simpleAuthentication Simple authentication to use in this message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapBindRequestLayer(uint16_t messageId, uint8_t version, const std::string& name,
		                     const std::string& simpleAuthentication,
		                     const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/**
		 * A constructor to create a new LDAP bind request message with SASL authentication
		 * @param[in] messageId The LDAP message ID
		 * @param[in] version The LDAP protocol version that the client wants to use
		 * @param[in] name The DN of the user to authenticate
		 * @param[in] saslAuthentication SASL authentication to use in this message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapBindRequestLayer(uint16_t messageId, uint8_t version, const std::string& name,
		                     const SaslAuthentication& saslAuthentication,
		                     const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/**
		 * @return The LDAP protocol version that the client wants to use
		 */
		uint32_t getVersion() const;

		/**
		 * @return The DN of the user to authenticate
		 */
		std::string getName() const;

		/**
		 * @return The authentication type included in this message
		 */
		AuthenticationType getAuthenticationType() const;

		/**
		 * @return The simple authentication included in this message
		 * @throws std::invalid_argument if the message doesn't include simple authentication
		 */
		std::string getSimpleAuthentication() const;

		/**
		 * @return The SASL authentication included in this message
		 * @throws std::invalid_argument if the message doesn't include SASL authentication
		 */
		SaslAuthentication getSaslAuthentication() const;

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapBindRequestLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                     Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}

		std::string getExtendedInfoString() const override;

	private:
		static constexpr int versionIndex = 0;
		static constexpr int nameIndex = 1;
		static constexpr int credentialIndex = 2;

		static constexpr int saslMechanismIndex = 0;
		static constexpr int saslCredentialsIndex = 1;
	};

	/**
	 * @class LdapBindResponseLayer
	 * Represents LDAP bind response operation
	 */
	class LdapBindResponseLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP bind response message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] serverSaslCredentials Encoded server SASL credentials for use in subsequent processing
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapBindResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                      const std::string& diagnosticMessage,
		                      const std::vector<std::string>& referral = std::vector<std::string>(),
		                      const std::vector<uint8_t>& serverSaslCredentials = std::vector<uint8_t>(),
		                      const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/**
		 * @return Encoded server SASL credentials for use in subsequent processing
		 */
		std::vector<uint8_t> getServerSaslCredentials() const;

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static constexpr int serverSaslCredentialsTagType = 7;

		LdapBindResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                      Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapUnbindRequestLayer
	 * Represents LDAP unbind operation
	 */
	class LdapUnbindRequestLayer : public LdapLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP unbind message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		explicit LdapUnbindRequestLayer(uint16_t messageId,
		                                const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		// Unbind request has no operation record
		Asn1ConstructedRecord* getLdapOperationAsn1Record() const = delete;

		LdapOperationType getLdapOperationType() const override
		{
			return LdapOperationType::UnbindRequest;
		}

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapUnbindRequestLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                       Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapSearchRequestLayer
	 * Represents LDAP search request operation
	 */
	class LdapSearchRequestLayer : public LdapLayer
	{
	public:
		/**
		 * @class SearchRequestScope
		 * An enum wrapper class for LDAP search request scope
		 */
		class SearchRequestScope
		{
		public:
			/**
			 * Define enum types and the corresponding int values
			 */
			enum Value : uint8_t
			{
				/**
				 * The search operation should only be performed against the entry specified as the search base DN
				 */
				BaseObject = 0,
				/**
				 * The search operation should only be performed against entries that are immediate subordinates
				 * of the entry specified as the search base DN
				 */
				SingleLevel = 1,
				/**
				 * The search operation should be performed against the entry specified as the search base
				 * and all of its subordinates to any depth
				 */
				WholeSubtree = 2,
				/**
				 * The search operation should be performed against any subordinate entries (to any depth) below the
				 * entry specified by the base DN should be considered, but the base entry itself
				 * should not be considered
				 */
				subordinateSubtree = 3,
				/**
				 * Unknown or unsupported scope
				 */
				Unknown = 255
			};

			SearchRequestScope() = default;

			// cppcheck-suppress noExplicitConstructor
			/**
			 * Construct SearchRequestScope from Value enum
			 * @param[in] value the scope enum value
			 */
			constexpr SearchRequestScope(Value value) : m_Value(value)
			{}

			/**
			 * @return A string representation of the scope value
			 */
			std::string toString() const;

			/**
			 * A static method that creates SearchRequestScope from an integer value
			 * @param[in] value The scope integer value
			 * @return The scope that corresponds to the integer value. If the integer value
			 * doesn't corresponds to any enum value, SearchRequestScope::Unknown is returned
			 */
			static SearchRequestScope fromUintValue(uint8_t value);

			// Allow switch and comparisons.
			constexpr operator Value() const
			{
				return m_Value;
			}

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;

		private:
			Value m_Value = SearchRequestScope::Unknown;
		};

		/**
		 * @class DerefAliases
		 * An enum wrapper class for LDAP search request dereferencing aliases
		 */
		class DerefAliases
		{
		public:
			/**
			 * Define enum types and the corresponding int values
			 */
			enum Value : uint8_t
			{
				/// Never dereferences aliases
				NeverDerefAliases = 0,
				/// Dereferences aliases only after name resolution
				DerefInSearching = 1,
				/// Dereferences aliases only during name resolution
				DerefFindingBaseObj = 2,
				/// Always dereference aliases
				DerefAlways = 3,
				/// Unknown value
				Unknown = 255
			};

			DerefAliases() = default;

			// cppcheck-suppress noExplicitConstructor
			/**
			 * Construct DerefAliases from Value enum
			 * @param[in] value the dereference alias enum value
			 */
			constexpr DerefAliases(Value value) : m_Value(value)
			{}

			/**
			 * @return A string representation of the dereference alias value
			 */
			std::string toString() const;

			/**
			 * A static method that creates DerefAliases from an integer value
			 * @param[in] value The dereference alias integer value
			 * @return The dereference alias that corresponds to the integer value. If the integer value
			 * doesn't corresponds to any enum value, DerefAliases::Unknown is returned
			 */
			static DerefAliases fromUintValue(uint8_t value);

			// Allow switch and comparisons.
			constexpr operator Value() const
			{
				return m_Value;
			}

			// Prevent usage: if(LdapOperationType)
			explicit operator bool() const = delete;

		private:
			Value m_Value = DerefAliases::Unknown;
		};

		/**
		 * A constructor to create a new LDAP search request message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] baseObject The base object for the LDAP search request entry
		 * @param[in] scope The portion of the target subtree that should be considered
		 * @param[in] derefAliases The alias dereferencing behavior, which indicates how the server should treat
		 * any aliases encountered while processing the search
		 * @param[in] sizeLimit The maximum number of entries that should be returned from the search
		 * @param[in] timeLimit The time limit for the search in seconds
		 * @param[in] typesOnly If this is given a value of true, then it indicates that entries that match the
		 * search criteria should be returned containing only the attribute descriptions for the attributes
		 * contained in that entry but should not include the values for those attributes.
		 * If this is given a value of false, then it indicates that the attribute values should be included
		 * in the entries that are returned
		 * @param[in] filterRecord The filter for the search. Please note that parsing for the search filter
		 * doesn't exist yet. Therefore, the expected input value should be a plain ASN.1 record
		 * @param[in] attributes A set of attributes to request for inclusion in entries that match the search
		 * criteria and are returned to the client
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapSearchRequestLayer(uint16_t messageId, const std::string& baseObject, SearchRequestScope scope,
		                       DerefAliases derefAliases, uint8_t sizeLimit, uint8_t timeLimit, bool typesOnly,
		                       Asn1Record* filterRecord, const std::vector<std::string>& attributes,
		                       const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/**
		 * @return The base object for the LDAP search request entry
		 */
		std::string getBaseObject() const;

		/**
		 * @return The portion of the target subtree that should be considered
		 */
		SearchRequestScope getScope() const;

		/**
		 * @return The alias dereferencing behavior
		 */
		DerefAliases getDerefAlias() const;

		/**
		 * @return The maximum number of entries that should be returned from the search
		 */
		uint8_t getSizeLimit() const;

		/**
		 * @return The time limit for the search in seconds
		 */
		uint8_t getTimeLimit() const;

		/**
		 * @return If this flag is true, then it indicates that entries that match the search criteria should be
		 * returned containing only the attribute descriptions for the attributes contained in that entry but
		 * should not include the values for those attributes. If this flag is false, then it indicates that the
		 * attribute values should be included in the entries that are returned
		 */
		bool getTypesOnly() const;

		/**
		 * @return The filter for the search. Please note that parsing for the search filter doesn't exist yet.
		 * Therefore, the return value is a plain ASN.1 record
		 */
		Asn1Record* getFilter() const;

		/**
		 * @return A list of search request attributes
		 */
		std::vector<std::string> getAttributes() const;

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static constexpr int baseObjectIndex = 0;
		static constexpr int scopeIndex = 1;
		static constexpr int derefAliasIndex = 2;
		static constexpr int sizeLimitIndex = 3;
		static constexpr int timeLimitIndex = 4;
		static constexpr int typesOnlyIndex = 5;
		static constexpr int filterIndex = 6;
		static constexpr int attributesIndex = 7;

		LdapSearchRequestLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                       Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}

		std::string getExtendedInfoString() const override;
	};

	/**
	 * @class LdapSearchResultEntryLayer
	 * Represents LDAP search result entry message
	 */
	class LdapSearchResultEntryLayer : public LdapLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP search result entry message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] objectName The entry's DN
		 * @param[in] attributes The entry's attributes
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapSearchResultEntryLayer(uint16_t messageId, const std::string& objectName,
		                           const std::vector<LdapAttribute>& attributes,
		                           const std::vector<LdapControl>& controls = std::vector<LdapControl>());

		/**
		 * @return The entry's DN
		 */
		std::string getObjectName() const;

		/**
		 * @return The entry's attributes
		 */
		std::vector<LdapAttribute> getAttributes() const;

		template <typename Method, typename ResultType> bool tryGet(Method method, ResultType& result)
		{
			return internalTryGet(this, method, result);
		}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		static constexpr int objectNameIndex = 0;
		static constexpr int attributesIndex = 1;
		static constexpr int attributeTypeIndex = 0;
		static constexpr int attributeValueIndex = 1;

		LdapSearchResultEntryLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                           Layer* prevLayer, Packet* packet)
		    : LdapLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapSearchResultDoneLayer
	 * Represents LDAP search result done message
	 */
	class LdapSearchResultDoneLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP search result done message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapSearchResultDoneLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                          const std::string& diagnosticMessage,
		                          const std::vector<std::string>& referral = std::vector<std::string>(),
		                          const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::SearchResultDone, resultCode, matchedDN,
		                        diagnosticMessage, referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapSearchResultDoneLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                          Layer* prevLayer, Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapModifyResponseLayer
	 * Represents LDAP modify response message
	 */
	class LdapModifyResponseLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP modify response message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapModifyResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                        const std::string& diagnosticMessage,
		                        const std::vector<std::string>& referral = std::vector<std::string>(),
		                        const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::ModifyResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapModifyResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                        Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapAddResponseLayer
	 * Represents LDAP add response message
	 */
	class LdapAddResponseLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP add response message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapAddResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                     const std::string& diagnosticMessage,
		                     const std::vector<std::string>& referral = std::vector<std::string>(),
		                     const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::AddResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapAddResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                     Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapDeleteResponseLayer
	 * Represents LDAP delete response message
	 */
	class LdapDeleteResponseLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP delete response message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapDeleteResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                        const std::string& diagnosticMessage,
		                        const std::vector<std::string>& referral = std::vector<std::string>(),
		                        const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::DeleteResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapDeleteResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen, Layer* prevLayer,
		                        Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapModifyDNResponseLayer
	 * Represents LDAP modify DN response message
	 */
	class LdapModifyDNResponseLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP modify DN response message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapModifyDNResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                          const std::string& diagnosticMessage,
		                          const std::vector<std::string>& referral = std::vector<std::string>(),
		                          const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::ModifyDNResponse, resultCode, matchedDN,
		                        diagnosticMessage, referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapModifyDNResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                          Layer* prevLayer, Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};

	/**
	 * @class LdapCompareResponseLayer
	 * Represents LDAP compare response message
	 */
	class LdapCompareResponseLayer : public LdapResponseLayer
	{
	public:
		/**
		 * A constructor to create a new LDAP compare response message
		 * @param[in] messageId The LDAP message ID
		 * @param[in] resultCode The LDAP result code
		 * @param[in] matchedDN The distinguished name (DN) to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] diagnosticMessage The additional information to set on the message. If not applicable
		 * pass an empty string
		 * @param[in] referral A list of URIs to re-try the operation somewhere else. This is an optional
		 * parameter. If not provided then referral won't be added to the message
		 * @param[in] controls A vector of LDAP controls. This is an optional parameter, if not provided the message
		 * will be created without LDAP controls
		 */
		LdapCompareResponseLayer(uint16_t messageId, LdapResultCode resultCode, const std::string& matchedDN,
		                         const std::string& diagnosticMessage,
		                         const std::vector<std::string>& referral = std::vector<std::string>(),
		                         const std::vector<LdapControl>& controls = std::vector<LdapControl>())
		    : LdapResponseLayer(messageId, LdapOperationType::CompareResponse, resultCode, matchedDN, diagnosticMessage,
		                        referral, controls)
		{}

	protected:
		friend LdapLayer* LdapLayer::parseLdapMessage(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		LdapCompareResponseLayer(std::unique_ptr<Asn1Record> asn1Record, uint8_t* data, size_t dataLen,
		                         Layer* prevLayer, Packet* packet)
		    : LdapResponseLayer(std::move(asn1Record), data, dataLen, prevLayer, packet)
		{}
	};
}  // namespace vanhooks::net

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::LdapControl& control)
{
	os << "{" << control.controlType << ", " << control.controlValue << "}";
	return os;
}

inline std::ostream& operator<<(std::ostream& os, const vanhooks::net::LdapAttribute& attr)
{
	os << "{" << attr.type << ", {";

	std::string separator;
	for (const auto& value : attr.values)
	{
		os << separator << value;
		if (separator.empty())
		{
			separator = ", ";
		}
	}

	os << "}}";
	return os;
}

inline std::ostream& operator<<(std::ostream& os,
                                const vanhooks::net::LdapBindRequestLayer::SaslAuthentication& saslAuthentication)
{
	os << "{" << saslAuthentication.mechanism << ", {";

	std::string separator;
	for (const auto& value : saslAuthentication.credentials)
	{
		os << separator << "0x" << std::hex << static_cast<int>(value) << std::dec;
		if (separator.empty())
		{
			separator = ", ";
		}
	}

	os << "}}";
	return os;
}
// ---- end LdapLayer.h ----

