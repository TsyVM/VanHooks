#pragma once

// ===== Consolidated header: NameServiceLayers.h =====
// Merges: DnsLayerEnums, DnsResourceData, DnsResource, DnsLayer, DhcpLayer, DhcpV6Layer
// Auto-consolidated for file-count reduction. All original upstream-derived
// functionality preserved verbatim; only file layout changed.

#include "Common.h"
#include "PacketCore.h"

// ---- begin DnsLayerEnums.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * An enum for all possible DNS record types
	 */
	enum DnsType
	{
		/** IPv4 address record */
		DNS_TYPE_A = 1,
		/** Name Server record */
		DNS_TYPE_NS,
		/** Obsolete, replaced by MX */
		DNS_TYPE_MD,
		/** Obsolete, replaced by MX */
		DNS_TYPE_MF,
		/** Canonical name record */
		DNS_TYPE_CNAME,
		/** Start of Authority record */
		DNS_TYPE_SOA,
		/** mailbox domain name record */
		DNS_TYPE_MB,
		/** mail group member record */
		DNS_TYPE_MG,
		/** mail rename domain name record */
		DNS_TYPE_MR,
		/** Null record */
		DNS_TYPE_NULL_R,
		/** well known service description record */
		DNS_TYPE_WKS,
		/** Pointer record */
		DNS_TYPE_PTR,
		/** Host information record */
		DNS_TYPE_HINFO,
		/** mailbox or mail list information record */
		DNS_TYPE_MINFO,
		/** Mail exchanger record */
		DNS_TYPE_MX,
		/** Text record */
		DNS_TYPE_TXT,
		/** Responsible person record */
		DNS_TYPE_RP,
		/** AFS database record */
		DNS_TYPE_AFSDB,
		/** DNS X25 resource record */
		DNS_TYPE_X25,
		/** Integrated Services Digital Network record */
		DNS_TYPE_ISDN,
		/** Route Through record */
		DNS_TYPE_RT,
		/** network service access point address record */
		DNS_TYPE_NSAP,
		/** network service access point address pointer record */
		DNS_TYPE_NSAP_PTR,
		/** Signature record */
		DNS_TYPE_SIG,
		/** Key record */
		DNS_TYPE_KEY,
		/** Mail Mapping Information record */
		DNS_TYPE_PX,
		/** DNS Geographical Position record */
		DNS_TYPE_GPOS,
		/** IPv6 address record */
		DNS_TYPE_AAAA,
		/** Location record */
		DNS_TYPE_LOC,
		/** Obsolete record */
		DNS_TYPE_NXT,
		/** DNS Endpoint Identifier record */
		DNS_TYPE_EID,
		/** DNS Nimrod Locator record */
		DNS_TYPE_NIMLOC,
		/** Service locator record */
		DNS_TYPE_SRV,
		/** Asynchronous Transfer Mode address record */
		DNS_TYPE_ATMA,
		/** Naming Authority Pointer record */
		DNS_TYPE_NAPTR,
		/** Key eXchanger record */
		DNS_TYPE_KX,
		/** Certificate record */
		DNS_TYPE_CERT,
		/** Obsolete, replaced by AAAA type */
		DNS_TYPE_A6,
		/** Delegation Name record */
		DNS_TYPE_DNAM,
		/** Kitchen sink record */
		DNS_TYPE_SINK,
		/** Option record */
		DNS_TYPE_OPT,
		/** Address Prefix List record */
		DNS_TYPE_APL,
		/** Delegation signer record */
		DNS_TYPE_DS,
		/** SSH Public Key Fingerprint record */
		DNS_TYPE_SSHFP,
		/** IPsec Key record */
		DNS_TYPE_IPSECKEY,
		/** DNSSEC signature record */
		DNS_TYPE_RRSIG,
		/** Next-Secure record */
		DNS_TYPE_NSEC,
		/** DNS Key record */
		DNS_TYPE_DNSKEY,
		/** DHCP identifier record */
		DNS_TYPE_DHCID,
		/** NSEC record version 3 */
		DNS_TYPE_NSEC3,
		/** NSEC3 parameters */
		DNS_TYPE_NSEC3PARAM,
		/** All cached records */
		DNS_TYPE_ALL = 255
	};

	/**
	 * An enum for all possible DNS classes
	 */
	enum DnsClass
	{
		/** Internet class */
		DNS_CLASS_IN = 1,
		/** Internet class with QU flag set to True */
		DNS_CLASS_IN_QU = 32769,
		/** Chaos class */
		DNS_CLASS_CH = 3,
		/** Hesiod class */
		DNS_CLASS_HS = 4,
		/** ANY class */
		DNS_CLASS_ANY = 255
	};

	/**
	 * An enum for representing the 4 types of possible DNS records
	 */
	enum DnsResourceType
	{
		/** DNS query record */
		DnsQueryType = 0,
		/** DNS answer record */
		DnsAnswerType = 1,
		/** DNS authority record */
		DnsAuthorityType = 2,
		/** DNS additional record */
		DnsAdditionalType = 3
	};

}  // namespace vanhooks::net
// ---- end DnsLayerEnums.h ----

// ---- begin DnsResourceData.h ----
#include <memory>
#include <string>
#include <stdint.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	// forward declarations
	class IDnsResource;

	/**
	 * @class IDnsResourceData
	 * A wrapper class for storing DNS RR (resource record) data. This is the base class which introduces several
	 * abstract methods for derived classes to implement for setting and retrieving the stored data. Each derived class
	 * will store different type of DNS RR data and implement these methods accordingly (for example: IPv4/IPv6
	 * addresses, MX data, hostnames, raw byte data etc.)
	 */
	class IDnsResourceData
	{
	protected:
		// unimplemented private copy c'tor
		IDnsResourceData(const IDnsResourceData& other);
		IDnsResourceData()
		{}

		size_t decodeName(const char* encodedName, char* result, IDnsResource* dnsResource) const;
		void encodeName(const std::string& decodedName, char* result, size_t& resultLen,
		                IDnsResource* dnsResource) const;

	public:
		/**
		 * A virtual d'tor, does nothing
		 */
		virtual ~IDnsResourceData()
		{}

		/**
		 * A templated method which takes a class that derives from IDnsResourceData as the template argument and
		 * checks whether this instance is of this type
		 * @return True if this instance is of the requested type, false otherwise
		 */
		template <class IDnsResourceDataType> bool isTypeOf() const
		{
			return dynamic_cast<const IDnsResourceDataType*>(this) != nullptr;
		}

		/**
		 * A templated method which take a class that derives from IDnsResourceData as the template argument and tries
		 * to cast the current instance as that type
		 * @return A pointer to the current instance casted as the requested type or nullptr if this instance isn't of
		 * this type
		 */
		template <class IDnsResourceDataType> IDnsResourceDataType* castAs()
		{
			return dynamic_cast<IDnsResourceDataType*>(this);
		}

		/**
		 * @return A string that represents the current DNS RR data
		 */
		virtual std::string toString() const = 0;

		/**
		 * Convert the DNS RR data into a byte array
		 * @param[out] arr A pointer to a pre-allocated byte array where the result will be written to
		 * @param[out] arrLength A reference to a 2-byte number where the result array length will be written to
		 * @param[in] dnsResource A pointer to a DNS resource object where this DNS RR data will be stored
		 * @return True if the DNS RR data was successfully converted into a byte array and written to the given array
		 * or false if stored DNS RR data is invalid or if it could not be written to the given array
		 */
		virtual bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const = 0;
	};

	/**
	 * @class DnsResourceDataPtr
	 * A smart pointer class that holds pointers of type IDnsResourceData. This object is used in DnsResource#getData()
	 */
	class DnsResourceDataPtr : public std::unique_ptr<IDnsResourceData>
	{
	public:
		/**
		 * A c'tor to this class
		 * @param[in] ptr A pointer to IDnsResourceData
		 */
		explicit DnsResourceDataPtr(IDnsResourceData* ptr) : std::unique_ptr<IDnsResourceData>(ptr)
		{}

		/**
		 * A templated method which takes a class that derives from IDnsResourceData as the template argument and
		 * checks whether the pointer stored in this object is of this type
		 * @return True if the stored pointer is of the requested type, false otherwise
		 */
		template <class IDnsResourceDataType> bool isTypeOf() const
		{
			return get()->isTypeOf<IDnsResourceDataType>();
		}

		/**
		 * A templated method which take a class that derives from IDnsResourceData as the template argument and tries
		 * to cast the pointer stored in this object as that type
		 * @return A pointer to the stored pointer casted as the requested type or nullptr if it isn't of this type
		 */
		template <class IDnsResourceDataType> IDnsResourceDataType* castAs()
		{
			return get()->castAs<IDnsResourceDataType>();
		}
	};

	/**
	 * @class StringDnsResourceData
	 * A class that represents DNS RR string data, mainly used in DNS RRs that store hostnames (like CNAME, DNAME, NS,
	 * etc.)
	 */
	class StringDnsResourceData : public IDnsResourceData
	{
	private:
		std::string m_Data;

	public:
		/**
		 * A c'tor for this class
		 * @param[in] data The string data to store in this object. If this string represents a hostname it's possible
		 * to include a pointer to another string in the DNS layer (as explained here:
		 * http://www.zytrax.com/books/dns/ch15/#name). These pointers are often used to reduce the DNS packet size and
		 * avoid unnecessary duplications. The way to include pointers in a hostname string is to use the following
		 * format: 'some.domain.#{offset}' where '#{offset}' is the offset from the start of the DNS layer. For example:
		 * if the string 'yahoo.com' already appears in offset 12 in the packet and you want to set the DNS RR data as
		 * 'my.subdomain.yahoo.com' you may use the following string: 'my.subdomain.#12'. This will result in writing
		 * 'my.subdomain' and a pointer to offset 12
		 */
		explicit StringDnsResourceData(const std::string& data) : m_Data(data)
		{}

		StringDnsResourceData(const uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource);

		~StringDnsResourceData()
		{}

		/**
		 * Equality operator overload for this class that compares the strings stored in each object
		 * @param[in] other The object to compare with
		 * @return True if the string data is the same in both objects, false otherwise
		 */
		bool operator==(const StringDnsResourceData& other) const
		{
			return m_Data == other.m_Data;
		}

		// implement abstract methods

		std::string toString() const
		{
			return m_Data;
		}
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const;
	};

	/**
	 * @class IPv4DnsResourceData
	 * A class that represents DNS RR IPv4 data, mainly used in DNS RRs of type ::DNS_TYPE_A
	 */
	class IPv4DnsResourceData : public IDnsResourceData
	{
	private:
		IPv4Address m_Data;

	public:
		/**
		 * A c'tor for this class
		 * @param[in] dataPtr A byte array of size 4 that contains an IPv4 address (each byte represents 1 octet)
		 * @param[in] dataLen The byte array size, expected to be 4
		 */
		IPv4DnsResourceData(const uint8_t* dataPtr, size_t dataLen);

		/**
		 * A c'tor for this class
		 * @param[in] addr The IPv4 address to store in this object
		 */
		explicit IPv4DnsResourceData(const IPv4Address& addr) : m_Data(addr)
		{}

		/**
		 * A c'tor for this class
		 * @param[in] addrAsString A string representation of an IPv4 address to store in this object
		 */
		explicit IPv4DnsResourceData(const std::string& addrAsString) : m_Data(addrAsString)
		{}

		/**
		 * Equality operator overload for this class that compares the IPv4 addresses stored in each object
		 * @param[in] other The object to compare with
		 * @return True if IPv4 addresses are the same in both objects, false otherwise
		 */
		bool operator==(const IPv4DnsResourceData& other) const
		{
			return m_Data == other.m_Data;
		}

		/**
		 * @return The IPv4 address stored in this object
		 */
		IPv4Address getIpAddress() const
		{
			return m_Data;
		}

		// implement abstract methods

		std::string toString() const
		{
			return m_Data.toString();
		}
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const;
	};

	/**
	 * @class IPv6DnsResourceData
	 * A class that represents DNS RR IPv6 data, mainly used in DNS RRs of type ::DNS_TYPE_AAAA
	 */
	class IPv6DnsResourceData : public IDnsResourceData
	{
	private:
		IPv6Address m_Data;

	public:
		/**
		 * A c'tor for this class
		 * @param[in] dataPtr A byte array of size 16 that contains an IPv6 address (each byte represents 1 octet)
		 * @param[in] dataLen The byte array size, expected to be 16
		 */
		IPv6DnsResourceData(const uint8_t* dataPtr, size_t dataLen);

		/**
		 * A c'tor for this class
		 * @param[in] addr The IPv6 address to store in this object
		 */
		explicit IPv6DnsResourceData(const IPv6Address& addr) : m_Data(addr)
		{}

		/**
		 * A c'tor for this class
		 * @param[in] addrAsString A string representation of an IPv6 address to store in this object
		 */
		explicit IPv6DnsResourceData(const std::string& addrAsString) : m_Data(addrAsString)
		{}

		/**
		 * Equality operator overload for this class that compares the IPv6 addresses stored in each object
		 * @param[in] other The object to compare with
		 * @return True if IPv6 addresses are the same in both objects, false otherwise
		 */
		bool operator==(const IPv6DnsResourceData& other) const
		{
			return m_Data == other.m_Data;
		}

		/**
		 * @return The IPv6 address stored in this object
		 */
		IPv6Address getIpAddress() const
		{
			return m_Data;
		}

		// implement abstract methods

		std::string toString() const
		{
			return m_Data.toString();
		}
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const;
	};

	/**
	 * @class MxDnsResourceData
	 * A class that represents DNS RR mail exchange (MX) data, used in DNS RRs of type ::DNS_TYPE_MX
	 */
	class MxDnsResourceData : public IDnsResourceData
	{
	public:
		/**
		 * A struct that represents mail exchange (MX) data
		 */
		struct MxData
		{
			/** Preference value */
			uint16_t preference;
			/** Mail exchange hostname */
			std::string mailExchange;
		};

		/**
		 * A c'tor for this class
		 * @param[in] dataPtr A byte array that contains the raw MX data (as written in the DNS packet)
		 * @param[in] dataLen The byte array size
		 * @param[in] dnsResource A pointer to a DNS resource object where this DNS RR data will be stored
		 */
		MxDnsResourceData(uint8_t* dataPtr, size_t dataLen, IDnsResource* dnsResource);

		/**
		 * A c'tor for this class
		 * @param[in] preference The MX preference value to store in this object
		 * @param[in] mailExchange The MX hostname value to store in this object. It's possible to include a pointer to
		 * another string in the DNS layer (as explained here: http://www.zytrax.com/books/dns/ch15/#name). These
		 * pointers are often used to reduce the DNS packet size and avoid unnecessary duplications. The way to include
		 * pointers in the hostname string is to use the following format: 'some.domain.#{offset}' where '#{offset}' is
		 * the offset from the start of the DNS layer. For example: if the string 'yahoo.com' already appears in offset
		 * 12 in the packet and you want to set the DNS RR data as 'my.subdomain.yahoo.com' you may use the following
		 * string: 'my.subdomain.#12'. This will result in writing 'my.subdomain' and a pointer to offset 12
		 */
		MxDnsResourceData(const uint16_t& preference, const std::string& mailExchange);

		~MxDnsResourceData()
		{}

		/**
		 * Equality operator overload for this class that compares the MX data stored in each object
		 * @param[in] other The object to compare with
		 * @return True if MX data is the same in both objects, meaning both preference and MX hostname are the same,
		 * false otherwise
		 */
		bool operator==(const MxDnsResourceData& other) const;

		/**
		 * @return The MX data stored in this object
		 */
		MxData getMxData() const
		{
			return m_Data;
		}

		/**
		 * Set the MX data stored in this object
		 * @param[in] preference The MX preference value to store in this object
		 * @param[in] mailExchange The MX hostname value to store in this object
		 */
		void setMxData(uint16_t preference, std::string mailExchange);

		// implement abstract methods

		/**
		 * A string representation of the MX data stored in this object. The string format is as follows:
		 * 'pref: {preference_value}; mx: {mail_exchange_hostname_value}'
		 */
		std::string toString() const;

		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const;

	private:
		MxData m_Data;
	};

	/**
	 * @class GenericDnsResourceData
	 * A class that represents generic DNS RR data which cannot be represented in any of the other classes. It stores
	 * the DNS RR data as byte array
	 */
	class GenericDnsResourceData : public IDnsResourceData
	{
	private:
		uint8_t* m_Data;
		size_t m_DataLen;

	public:
		/**
		 * A c'tor for this class
		 * @param[in] dataPtr A byte array that contains the raw data (as it written in the DNS packet). The data will
		 * be copied from this byte array to the object
		 * @param[in] dataLen The byte array size
		 */
		GenericDnsResourceData(const uint8_t* dataPtr, size_t dataLen);

		/**
		 * A c'tor for this class
		 * @param[in] dataAsHexString A hex string that represents the DNS RR data
		 */
		explicit GenericDnsResourceData(const std::string& dataAsHexString);

		/**
		 * A copy c'tor for this class
		 * @param[in] other The instance to copy from
		 */
		GenericDnsResourceData(const GenericDnsResourceData& other);

		~GenericDnsResourceData()
		{
			if (m_Data != nullptr)
				delete[] m_Data;
		}

		GenericDnsResourceData& operator=(const GenericDnsResourceData& other);

		/**
		 * Equality operator overload for this class that compares the raw data stored in each object
		 * @param[in] other The object to compare with
		 * @return True if data is the same in both objects, meaning byte streams are equal, false otherwise
		 */
		bool operator==(const GenericDnsResourceData& other) const;

		// implement abstract methods

		std::string toString() const;
		bool toByteArr(uint8_t* arr, size_t& arrLength, IDnsResource* dnsResource) const;
	};

}  // namespace vanhooks::net
// ---- end DnsResourceData.h ----

// ---- begin DnsResource.h ----
#include <stdio.h>
#include <string>
#include <stdint.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	// forward declarations
	class DnsLayer;
	class IDnsResourceData;
	class DnsResourceDataPtr;

	/**
	 * @class IDnsResource
	 * An abstract class for representing all types of DNS records. This class gives access to all available record data
	 * such as DNS type, class, name, type of record, etc. The DnsLayer holds an instance of (inherited type of) this
	 * class for each DNS record in the DNS packet
	 */
	class IDnsResource
	{
	protected:
		friend class DnsLayer;
		friend class IDnsResourceData;

	protected:
		DnsLayer* m_DnsLayer;
		size_t m_OffsetInLayer;
		IDnsResource* m_NextResource;
		std::string m_DecodedName;
		size_t m_NameLength;
		uint8_t* m_ExternalRawData;

		IDnsResource(DnsLayer* dnsLayer, size_t offsetInLayer);

		IDnsResource(uint8_t* emptyRawData);

		size_t decodeName(const char* encodedName, char* result, int iteration = 1);
		void encodeName(const std::string& decodedName, char* result, size_t& resultLen);

		IDnsResource* getNextResource() const
		{
			return m_NextResource;
		}
		void setNextResource(IDnsResource* next)
		{
			m_NextResource = next;
		}

		uint8_t* getRawData() const;

		void setDnsLayer(DnsLayer* dnsLayer, size_t offsetInLayer);

	public:
		virtual ~IDnsResource()
		{}

		/**
		 * @return The DNS type of this record
		 */
		DnsType getDnsType() const;

		/**
		 * Set DNS type for this record
		 * @param[in] newType The type to set
		 */
		void setDnsType(DnsType newType);

		/**
		 * @return The DNS class of this record
		 */
		DnsClass getDnsClass() const;

		/**
		 * Set DNS class for this record
		 * @param[in] newClass The class to set
		 */
		void setDnsClass(DnsClass newClass);

		/**
		 * @return The name of this record
		 */
		const std::string& getName() const
		{
			return m_DecodedName;
		}

		/**
		 * @return The record name's offset in the packet
		 */
		size_t getNameOffset() const
		{
			return m_OffsetInLayer;
		}

		/**
		 * Set the name of this record. The input name can be a standard hostname (e.g 'google.com'), or it may contain
		 * a pointer to another string in the packet (as explained here: http://www.zytrax.com/books/dns/ch15/#name).
		 * The pointer is used to reduce the DNS packet size and avoid unnecessary duplications. In case you
		 * want to use a pointer in your string you should use the following format: 'some.domain.#{offset}' where
		 * '#{offset}' is a the offset from the start of the layer. For example: if the string 'yahoo.com' already
		 * appears in offset 12 in the packet and you want to set the name of the current record to
		 * 'my.subdomain.yahoo.com' you may use the following string: 'my.subdomain.#12'. This will result in writing
		 * 'my.subdomain' and a pointer to offset 12.<BR> Please notice the new name can be shorter or longer of the old
		 * name, so this method can cause the packet to be shorten or extended
		 * @param[in] newName The name to set
		 * @return True if name was set successfully or false if input string is malformed or if an error occurred
		 */
		bool setName(const std::string& newName);

		// abstract methods

		/**
		 * @return The total size in bytes of this record
		 */
		virtual size_t getSize() const = 0;

		/**
		 * @return The type of this record (query, answer, authority, additional)
		 */
		virtual DnsResourceType getType() const = 0;
	};

	/**
	 * @class DnsQuery
	 * Representing a DNS query record
	 */
	class DnsQuery : public IDnsResource
	{
		friend class DnsLayer;

	private:
		DnsQuery(DnsLayer* dnsLayer, size_t offsetInLayer) : IDnsResource(dnsLayer, offsetInLayer)
		{}

		explicit DnsQuery(uint8_t* emptyRawData) : IDnsResource(emptyRawData)
		{}

	public:
		virtual ~DnsQuery()
		{}

		// implementation of abstract methods
		virtual size_t getSize() const
		{
			return m_NameLength + 2 * sizeof(uint16_t);
		}
		virtual DnsResourceType getType() const
		{
			return DnsQueryType;
		}
	};

	/**
	 * @class DnsResource
	 * Representing DNS record other than DNS query
	 */
	class DnsResource : public IDnsResource
	{
		friend class DnsLayer;

	private:
		DnsResourceType m_ResourceType;

		DnsResource(DnsLayer* dnsLayer, size_t offsetInLayer, DnsResourceType resourceType)
		    : IDnsResource(dnsLayer, offsetInLayer)
		{
			m_ResourceType = resourceType;
		}

		DnsResource(uint8_t* emptyRawData, DnsResourceType resType)
		    : IDnsResource(emptyRawData), m_ResourceType(resType)
		{}

	public:
		virtual ~DnsResource()
		{}

		/**
		 * @return The time-to-leave value for this record
		 */
		uint32_t getTTL() const;

		/**
		 * Set time-to-leave value for this record
		 * @param[in] newTTL The new TTL value to set
		 */
		void setTTL(uint32_t newTTL);

		/**
		 * @return The data length value for this record (taken from the "data length" field of the record)
		 */
		size_t getDataLength() const;

		/**
		 * @return A smart pointer to an IDnsResourceData object that contains the DNS resource data. It is guaranteed
		 * that the smart pointer will always point to an object and never to nullptr. The specific object type depends
		 * on the DNS type of this record:<BR>
		 * - For type A (::DNS_TYPE_A): the return value is a smart pointer to IPv4DnsResourceData object that contains
		 * the IPv4 address<BR>
		 * - For type AAAA (::DNS_TYPE_AAAA): the return value is a smart pointer to IPv6DnsResourceData object that
		 * contains the IPv6 address<BR>
		 * - For types NS, CNAME, DNAME, PTR (::DNS_TYPE_NS, ::DNS_TYPE_CNAME, ::DNS_TYPE_DNAM, ::DNS_TYPE_PTR): the
		 * return value is a smart pointer to StringDnsResourceData object that contains the name<BR>
		 * - For type MX (::DNS_TYPE_MX): the return value is a smart pointer to MxDnsResourceData object that contains
		 * the MX data (preference and mail exchange name)<BR>
		 * - For all other types: the return value is a smart pointer to GenericDnsResourceData which contains a byte
		 * array of the data
		 */
		DnsResourceDataPtr getData() const;

		/**
		 * @return The offset of data in the DNS layer
		 */
		size_t getDataOffset() const;

		/**
		 * Set resource data. The given IDnsResourceData input object is validated against the DNS type of the resource.
		 * For example: if DNS type is A and data isn't of type IPv4DnsResourceData (which contains the IPv4 address) a
		 * log error will be printed and the method will return false. This method currently supports the following DNS
		 * types:<BR>
		 * - ::DNS_TYPE_A (IPv4 address) - data is expected to be a pointer to IPv4DnsResourceData with a valid IPv4
		 * address
		 * - ::DNS_TYPE_AAAA (IPv6 address) - data is expected to be a pointer to IPv6DnsResourceData with a valid IPv6
		 * address
		 * - ::DNS_TYPE_NS, ::DNS_TYPE_CNAME, ::DNS_TYPE_DNAM, ::DNS_TYPE_PTR (name data) - data is expected to be a
		 * pointer to StringDnsResourceData object that contains a host name, e.g: 'www.google.com'
		 * - ::DNS_TYPE_MX (MX data) - data is expected to be a pointer to MxDnsResourceData object that contains the MX
		 * data
		 * - else: data is expected to be a pointer to GenericDnsResourceData object that contains a valid hex string
		 * (valid hex string means a string which has an even number of characters representing a valid hex data. e.g:
		 * '0d0a45569a9b')
		 * @param[in] data The pointer to the data object, as described above
		 * @return True if data was properly set or false if data is illegal or method couldn't extend or shorted the
		 * packet (appropriate error log is printed in all cases)
		 */
		bool setData(IDnsResourceData* data);

		/**
		 * Some records don't have a DNS class and the bytes used for storing the DNS class are used for other purpose.
		 * This method enables the user to receive these bytes
		 * @return The value stored in this place
		 */
		uint16_t getCustomDnsClass() const;

		/**
		 * Some records don't have a DNS class and the bytes used for storing the DNS class are used for other purpose.
		 * This method enables the user to set these bytes
		 * @param[in] customValue The value to set
		 */
		void setCustomDnsClass(uint16_t customValue);

		// implementation of abstract methods
		virtual size_t getSize() const
		{
			return m_NameLength + 3 * sizeof(uint16_t) + sizeof(uint32_t) + getDataLength();
		}
		virtual DnsResourceType getType() const
		{
			return m_ResourceType;
		}
	};

}  // namespace vanhooks::net
// ---- end DnsResource.h ----

// ---- begin DnsLayer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

	/**
	 * @struct dnshdr
	 * Represents the fixed part of the DNS header, meaning the part that doesn't include the DNS data (queries,
	 * answers, authorities and additional records)
	 */
#pragma pack(push, 1)
	struct dnshdr
	{
		/** DNS query identification */
		uint16_t transactionID;
#if (BYTE_ORDER == LITTLE_ENDIAN)
		uint16_t
		    /** Recursion desired flag */
		    recursionDesired : 1,
		    /** Truncated flag */
		    truncation : 1,
		    /** Authoritative answer flag */
		    authoritativeAnswer : 1,
		    /** Operation Code */
		    opcode : 4,
		    /** Query/Response flag */
		    queryOrResponse : 1,
		    /** Return Code */
		    responseCode : 4,
		    /** Checking disabled flag */
		    checkingDisabled : 1,
		    /** Authenticated data flag */
		    authenticData : 1,
		    /** Zero flag (Reserved) */
		    zero : 1,
		    /** Recursion available flag */
		    recursionAvailable : 1;
#elif (BYTE_ORDER == BIG_ENDIAN)
		uint16_t
		    /** Query/Response flag */
		    queryOrResponse : 1,
		    /** Operation Code */
		    opcode : 4,
		    /** Authoritative answer flag */
		    authoritativeAnswer : 1,
		    /** Truncated flag */
		    truncation : 1,
		    /** Recursion desired flag */
		    recursionDesired : 1,
		    /** Recursion available flag */
		    recursionAvailable : 1,
		    /** Zero flag (Reserved) */
		    zero : 1,
		    /** Authenticated data flag */
		    authenticData : 1,
		    /** Checking disabled flag */
		    checkingDisabled : 1,
		    /** Return Code */
		    responseCode : 4;
#endif
		/** Number of DNS query records in packet */
		uint16_t numberOfQuestions;
		/** Number of DNS answer records in packet */
		uint16_t numberOfAnswers;
		/** Number of authority records in packet */
		uint16_t numberOfAuthority;
		/** Number of additional records in packet */
		uint16_t numberOfAdditional;
	};
#pragma pack(pop)

	// forward declarations
	class DnsQuery;
	class IDnsResource;
	class DnsResource;
	class IDnsResourceData;

	/**
	 * @class DnsLayer
	 * Represents the DNS protocol layer
	 */
	class DnsLayer : public Layer
	{
		friend class IDnsResource;
		friend class DnsQuery;
		friend class DnsResource;

	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates an empty DNS layer: all members of dnshdr are set to 0 and layer will contain no
		 * records
		 */
		DnsLayer();

		/**
		 * A copy constructor for this layer
		 * @param[in] other The DNS layer to copy from
		 */
		DnsLayer(const DnsLayer& other);

		/**
		 * An assignment operator for this layer
		 * @param[in] other The DNS layer to assign
		 * @return A reference to the assignee
		 */
		DnsLayer& operator=(const DnsLayer& other);

		virtual ~DnsLayer();

		/**
		 * Get a pointer to the DNS header (as opposed to the DNS data which is the queries, answers, etc. Data can be
		 * retrieved through the other methods of this layer. Notice the return value points directly to the data, so
		 * every change will change the actual packet data
		 * @return A pointer to the @ref dnshdr
		 */
		dnshdr* getDnsHeader() const;

		/**
		 * Searches for a DNS query by its name field. Notice this method returns only a query which its name equals to
		 * the requested name. If several queries match the requested name, the first one will be returned. If no
		 * queries match the requested name, nullptr will be returned
		 * @param[in] name The name of the query to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS query or nullptr if no queries were found
		 */
		DnsQuery* getQuery(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS query in the packet or nullptr if packet doesn't contain any queries
		 */
		DnsQuery* getFirstQuery() const;

		/**
		 * Get the DNS query following a certain query
		 * @param[in] query A pointer to a DNS query that exist in the packet
		 * @return The DNS query following 'query'. If 'query' is nullptr or 'query' is the last query in the packet
		 * nullptr will be returned
		 */
		DnsQuery* getNextQuery(DnsQuery* query) const;

		/**
		 * @return The number of DNS queries in the packet
		 */
		size_t getQueryCount() const;

		/**
		 * Add a new DNS query to the layer
		 * @param[in] name The value that shall be set in the name field of the query
		 * @param[in] dnsType The value that shall be set in the DNS type field of the query
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the query
		 * @return A pointer to the newly created DNS query or nullptr if query could not be created (an appropriate
		 * error log message will be printed in this case)
		 */
		DnsQuery* addQuery(const std::string& name, DnsType dnsType, DnsClass dnsClass);

		/**
		 * Add a new DNS query similar to an already existing DNS query. All query fields will be copied from the
		 * existing query
		 * @param[in] copyQuery The record to create the new record from. copyQuery won't be changed in any way
		 * @return A pointer to the newly created DNS query or nullptr if query could not be created (an appropriate
		 * error log message will be printed in this case)
		 */
		DnsQuery* addQuery(DnsQuery* const copyQuery);

		/**
		 * Remove an existing query by name. If several queries matches the name, the first match will be removed
		 * @param[in] queryNameToRemove The name of the query to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if query was found and successfully removed or false if query was not found or couldn't be
		 * removed
		 */
		bool removeQuery(const std::string& queryNameToRemove, bool exactMatch);

		/**
		 * Remove an existing query
		 * @param[in] queryToRemove A pointer to the query to remove
		 * @return True if query was found and successfully removed or false if query was not found or couldn't be
		 * removed
		 */
		bool removeQuery(DnsQuery* queryToRemove);

		/**
		 * Searches for a DNS answer by its name field. Notice this method returns only an answer which its name equals
		 * to the requested name. If several answers match the requested name, the first one will be returned. If no
		 * answers match the requested name, nullptr will be returned
		 * @param[in] name The name of the answer to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS answer or nullptr if no answers were found
		 */
		DnsResource* getAnswer(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS answer in the packet or nullptr if packet doesn't contain any answers
		 */
		DnsResource* getFirstAnswer() const;

		/**
		 * Get the DNS answer following a certain answer
		 * @param[in] answer A pointer to a DNS answer that exist in the packet
		 * @return The DNS answer following 'answer'. If 'answer' is nullptr or 'answer' is the last answer in the
		 * packet nullptr will be returned
		 */
		DnsResource* getNextAnswer(DnsResource* answer) const;

		/**
		 * @return The number of DNS answers in the packet
		 */
		size_t getAnswerCount() const;

		/**
		 * Add a new DNS answer to the layer
		 * @param[in] name The value that shall be set in the name field of the answer
		 * @param[in] dnsType The value that shall be set in the DNS type field of the answer
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the answer
		 * @param[in] ttl The value that shall be set in the 'time-to-leave' field of the answer
		 * @param[in] data The answer data to be set. The type of the data should match the type of the DNS record
		 * (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see
		 * DnsResource#setData() for more info on this
		 * @return A pointer to the newly created DNS answer or nullptr if answer could not be created (an appropriate
		 * error log message will be printed in this case)
		 */
		DnsResource* addAnswer(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl,
		                       IDnsResourceData* data);

		/**
		 * Add a new DNS answer similar to an already existing DNS answer. All answer fields will be copied from the
		 * existing answer
		 * @param[in] copyAnswer The record to create the new record from. copyAnswer won't be changed in any way
		 * @return A pointer to the newly created DNS answer or nullptr if query could not be created (an appropriate
		 * error log message will be printed in this case)
		 */
		DnsResource* addAnswer(DnsResource* const copyAnswer);

		/**
		 * Remove an existing answer by name. If several answers matches the name, the first match will be removed
		 * @param[in] answerNameToRemove The name of the answer to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if answer was found and successfully removed or false if answer was not found or couldn't be
		 * removed
		 */
		bool removeAnswer(const std::string& answerNameToRemove, bool exactMatch);

		/**
		 * Remove an existing answer
		 * @param[in] answerToRemove A pointer to the answer to remove
		 * @return True if answer was found and successfully removed or false if answer was not found or couldn't be
		 * removed
		 */
		bool removeAnswer(DnsResource* answerToRemove);

		/**
		 * Searches for a DNS authority by its name field. Notice this method returns only an authority which its name
		 * equals to the requested name. If several authorities match the requested name, the first one will be
		 * returned. If no authorities match the requested name, nullptr will be returned
		 * @param[in] name The name of the authority to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS authority or nullptr if no authorities were found
		 */
		DnsResource* getAuthority(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS authority in the packet or nullptr if packet doesn't contain any authorities
		 */
		DnsResource* getFirstAuthority() const;

		/**
		 * Get the DNS authority following a certain authority
		 * @param[in] authority A pointer to a DNS authority that exist in the packet
		 * @return The DNS authority following 'authority'. If 'authority' is nullptr or 'authority' is the last
		 * authority in the packet nullptr will be returned
		 */
		DnsResource* getNextAuthority(DnsResource* authority) const;

		/**
		 * @return The number of DNS authorities in the packet
		 */
		size_t getAuthorityCount() const;

		/**
		 * Add a new DNS authority to the layer
		 * @param[in] name The value that shall be set in the name field of the authority
		 * @param[in] dnsType The value that shall be set in the DNS type field of the authority
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the authority
		 * @param[in] ttl The value that shall be set in the 'time-to-leave' field of the authority
		 * @param[in] data The authority data to be set. The type of the data should match the type of the DNS record
		 * (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see
		 * DnsResource#setData() for more info on this
		 * @return A pointer to the newly created DNS authority or nullptr if authority could not be created (an
		 * appropriate error log message will be printed in this case)
		 */
		DnsResource* addAuthority(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl,
		                          IDnsResourceData* data);

		/**
		 * Add a new DNS authority similar to an already existing DNS authority. All authority fields will be copied
		 * from the existing authority
		 * @param[in] copyAuthority The record to create the new record from. copyAuthority won't be changed in any way
		 * @return A pointer to the newly created DNS authority or nullptr if query could not be created (an appropriate
		 * error log message will be printed in this case)
		 */
		DnsResource* addAuthority(DnsResource* const copyAuthority);

		/**
		 * Remove an existing authority by name. If several authorities matches the name, the first match will be
		 * removed
		 * @param[in] authorityNameToRemove The name of the authority to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if authority was found and successfully removed or false if authority was not found or couldn't
		 * be removed
		 */
		bool removeAuthority(const std::string& authorityNameToRemove, bool exactMatch);

		/**
		 * Remove an existing authority
		 * @param[in] authorityToRemove A pointer to the authority to remove
		 * @return True if authority was found and successfully removed or false if authority was not found or couldn't
		 * be removed
		 */
		bool removeAuthority(DnsResource* authorityToRemove);

		/**
		 * Searches for a DNS additional record by its name field. Notice this method returns only an additional record
		 * which its name equals to the requested name. If several additional records match the requested name, the
		 * first one will be returned. If no additional records match the requested name, nullptr will be returned
		 * @param[in] name The name of the additional record to search
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return The first matching DNS additional record or nullptr if no additional records were found
		 */
		DnsResource* getAdditionalRecord(const std::string& name, bool exactMatch) const;

		/**
		 * @return The first DNS additional record in the packet or nullptr if packet doesn't contain any additional
		 * records
		 */
		DnsResource* getFirstAdditionalRecord() const;

		/**
		 * Get the DNS additional record following a certain additional record
		 * @param[in] additionalRecord A pointer to a DNS additional record that exist in the packet
		 * @return The DNS additional record following 'additionalRecord'. If 'additionalRecord' is nullptr or
		 * 'additionalRecord' is the last additional record in the packet nullptr will be returned
		 */
		DnsResource* getNextAdditionalRecord(DnsResource* additionalRecord) const;

		/**
		 * @return The number of DNS additional records in the packet
		 */
		size_t getAdditionalRecordCount() const;

		/**
		 * Add a new DNS additional record to the layer
		 * @param[in] name The value that shall be set in the name field of the additional record
		 * @param[in] dnsType The value that shall be set in the DNS type field of the additional record
		 * @param[in] dnsClass The value that shall be set in the DNS class field of the additional record
		 * @param[in] ttl The value that shall be set in the 'time-to-leave' field of the additional record
		 * @param[in] data The additional record data to be set. The type of the data should match the type of the DNS
		 * record (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see
		 * DnsResource#setData() for more info on this
		 * @return A pointer to the newly created DNS additional record or nullptr if additional record could not be
		 * created (an appropriate error log message will be printed in this case)
		 */
		DnsResource* addAdditionalRecord(const std::string& name, DnsType dnsType, DnsClass dnsClass, uint32_t ttl,
		                                 IDnsResourceData* data);

		/**
		 * Add a new DNS additional record to the layer that doesn't have DNS class and TTL. Instead these bytes may
		 * contains some arbitrary data. In the future I may add support for these kinds of additional data records. For
		 * now, these bytes are set as raw
		 * @param[in] name The value that shall be set in the name field of the additional record
		 * @param[in] dnsType The value that shall be set in the DNS type field of the additional record
		 * @param[in] customData1 Two bytes of the arbitrary data that will be set in the offset usually used for the
		 * DNS class
		 * @param[in] customData2 Four bytes of the arbitrary data that will be set in the offset usually used for the
		 * TTL
		 * @param[in] data The additional record data to be set. The type of the data should match the type of the DNS
		 * record. (for example: DNS record of type A should have data of type IPv4DnsResourceData. Please see
		 * DnsResource#setData() for more info on this
		 * @return A pointer to the newly created DNS additional record or nullptr if additional record could not be
		 * created (an appropriate error log message will be printed in this case)
		 */
		DnsResource* addAdditionalRecord(const std::string& name, DnsType dnsType, uint16_t customData1,
		                                 uint32_t customData2, IDnsResourceData* data);

		/**
		 * Add a new DNS additional record similar to an already existing DNS additional record. All additional record
		 * fields will be copied from the existing additional record
		 * @param[in] copyAdditionalRecord The record to create the new record from. copyAdditionalRecord won't be
		 * changed in any way
		 * @return A pointer to the newly created DNS additional record or nullptr if query could not be created (an
		 * appropriate error log message will be printed in this case)
		 */
		DnsResource* addAdditionalRecord(DnsResource* const copyAdditionalRecord);

		/**
		 * Remove an existing additional record by name. If several additional records matches the name, the first match
		 * will be removed
		 * @param[in] additionalRecordNameToRemove The name of the additional record to remove
		 * @param[in] exactMatch Indicate whether to match the whole name or just a part of it
		 * @return True if additional record was found and successfully removed or false if additional record was not
		 * found or couldn't be removed
		 */
		bool removeAdditionalRecord(const std::string& additionalRecordNameToRemove, bool exactMatch);

		/**
		 * Remove an existing additional record
		 * @param[in] additionalRecordToRemove A pointer to the additional record to remove
		 * @return True if additional record was found and successfully removed or false if additional record was not
		 * found or couldn't be removed
		 */
		bool removeAdditionalRecord(DnsResource* additionalRecordToRemove);

		// implement abstract methods

		/**
		 * Does nothing for this layer (DnsLayer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return The size of the DNS data in the packet including he DNS header and size of all queries, answers,
		 * authorities and additional records
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}  // No layer above DNS

		/**
		 * Does nothing for this layer
		 */
		virtual void computeCalculateFields()
		{}

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

		/**
		 * A static method that checks whether the port is considered as DNS
		 * @param[in] port The port number to be checked
		 * @return True if the port is associated with the DNS protocol
		 */
		static inline bool isDnsPort(uint16_t port);

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of a DNS packet
		 * @param[in] dataLen The length of the byte stream
		 * @param[in] dnsOverTcp Should be set to "true" if this is DNS is over TCP, otherwise set to "false"
		 * (which is also the default value)
		 * @return True if the data is valid and can represent a DNS packet
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen, bool dnsOverTcp = false);

	protected:
		DnsLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet, size_t offsetAdjustment);
		explicit DnsLayer(size_t offsetAdjustment);

	private:
		IDnsResource* m_ResourceList;
		DnsQuery* m_FirstQuery;
		DnsResource* m_FirstAnswer;
		DnsResource* m_FirstAuthority;
		DnsResource* m_FirstAdditional;
		uint16_t m_OffsetAdjustment;

		size_t getBasicHeaderSize();
		void init(size_t offsetAdjustment, bool callParseResource);
		void initNewLayer(size_t offsetAdjustment);

		IDnsResource* getFirstResource(DnsResourceType resType) const;
		void setFirstResource(DnsResourceType resType, IDnsResource* resource);

		using Layer::extendLayer;
		bool extendLayer(int offsetInLayer, size_t numOfBytesToExtend, IDnsResource* resource);

		using Layer::shortenLayer;
		bool shortenLayer(int offsetInLayer, size_t numOfBytesToShorten, IDnsResource* resource);

		IDnsResource* getResourceByName(IDnsResource* startFrom, size_t resourceCount, const std::string& name,
		                                bool exactMatch) const;

		void parseResources();

		DnsResource* addResource(DnsResourceType resType, const std::string& name, DnsType dnsType, DnsClass dnsClass,
		                         uint32_t ttl, IDnsResourceData* data);

		bool removeResource(IDnsResource* resourceToRemove);
	};

	/**
	 * @class DnsOverTcpLayer
	 * Represents the DNS over TCP layer.
	 * DNS over TCP is described here: https://tools.ietf.org/html/rfc7766 .
	 * It is very similar to DNS over UDP, except for one field: TCP message length which is added in the beginning of
	 * the message before the other DNS data properties. The rest of the data is similar.
	 *
	 * Note: DNS over TCP can spread over more than one packet, but this implementation doesn't support this use-case
	 * and assumes the whole message fits in a single packet.
	 */
	class DnsOverTcpLayer : public DnsLayer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DnsOverTcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
		    : DnsLayer(data, dataLen, prevLayer, packet, sizeof(uint16_t))
		{}

		/**
		 * A constructor that creates an empty DNS layer: all members of dnshdr are set to 0 and layer will contain no
		 * records
		 */
		DnsOverTcpLayer() : DnsLayer(sizeof(uint16_t))
		{}

		/**
		 * A copy constructor for this layer
		 * @param[in] other The DNS over TCP layer to copy from
		 */
		DnsOverTcpLayer(const DnsOverTcpLayer& other) : DnsLayer(other)
		{}

		/**
		 * @return The value of the TCP message length as described in https://tools.ietf.org/html/rfc7766#section-8
		 */
		uint16_t getTcpMessageLength();

		/**
		 * Set the TCP message length value as described in https://tools.ietf.org/html/rfc7766#section-8
		 * @param[in] value The value to set
		 */
		void setTcpMessageLength(uint16_t value);

		// overridden methods

		/**
		 * Calculate the TCP message length field
		 */
		void computeCalculateFields();
	};

	// implementation of inline methods

	bool DnsLayer::isDnsPort(uint16_t port)
	{
		switch (port)
		{
		case 53:
		case 5353:
		case 5355:
			return true;
		default:
			return false;
		}
	}

	bool DnsLayer::isDataValid(const uint8_t* data, size_t dataLen, bool dnsOverTcp)
	{
		size_t minSize = sizeof(dnshdr) + (dnsOverTcp ? sizeof(uint16_t) : 0);
		return data && dataLen >= minSize;
	}

}  // namespace vanhooks::net
// ---- end DnsLayer.h ----

// ---- begin DhcpLayer.h ----
#include <string.h>

/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{

/**
 * @struct dhcp_header
 * Represents a DHCP protocol header
 */
#pragma pack(push, 1)
	struct dhcp_header
	{
		/** BootP opcode */
		uint8_t opCode;
		/** Hardware type, set to 1 (Ethernet) by default */
		uint8_t hardwareType;
		/** Hardware address length, set to 6 (MAC address length) by default */
		uint8_t hardwareAddressLength;
		/** Hop count */
		uint8_t hops;
		/** DHCP/BootP transaction ID */
		uint32_t transactionID;
		/** The elapsed time, in seconds since the client sent its first BOOTREQUEST message */
		uint16_t secondsElapsed;
		/** BootP flags */
		uint16_t flags;
		/** Client IPv4 address */
		uint32_t clientIpAddress;
		/** Your IPv4 address */
		uint32_t yourIpAddress;
		/** Server IPv4 address */
		uint32_t serverIpAddress;
		/** Gateway IPv4 address */
		uint32_t gatewayIpAddress;
		/** Client hardware address, by default contains the MAC address (only 6 first bytes are used) */
		uint8_t clientHardwareAddress[16];
		/** BootP server name */
		uint8_t serverName[64];
		/** BootP boot file name */
		uint8_t bootFilename[128];
		/** DHCP magic number (set to the default value of 0x63538263) */
		uint32_t magicNumber;
	};
#pragma pack(pop)

	/**
	 * BootP opcodes
	 */
	enum BootpOpCodes
	{
		/** BootP request */
		DHCP_BOOTREQUEST = 1,
		/** BootP reply */
		DHCP_BOOTREPLY = 2
	};

	/**
	 * DHCP message types
	 */
	enum DhcpMessageType
	{
		/** Unknown message type */
		DHCP_UNKNOWN_MSG_TYPE = 0,
		/** Discover message type */
		DHCP_DISCOVER = 1,
		/** Offer message type */
		DHCP_OFFER = 2,
		/** Request message type */
		DHCP_REQUEST = 3,
		/** Decline message type */
		DHCP_DECLINE = 4,
		/** Acknowledge message type */
		DHCP_ACK = 5,
		/** Non-acknowledge message type */
		DHCP_NAK = 6,
		/** Release message type */
		DHCP_RELEASE = 7,
		/** Inform message type */
		DHCP_INFORM = 8
	};

	/**
	 * DHCP option types.
	 */
	enum DhcpOptionTypes
	{
		/** Unknown option type */
		DHCPOPT_UNKNOWN = -1,
		/** Pad */
		DHCPOPT_PAD = 0,
		/** Subnet Mask Value */
		DHCPOPT_SUBNET_MASK = 1,
		/** Time Offset in Seconds from UTC */
		DHCPOPT_TIME_OFFSET = 2,
		/** N/4 Router addresses */
		DHCPOPT_ROUTERS = 3,
		/** N/4 Timeserver addresses */
		DHCPOPT_TIME_SERVERS = 4,
		/** N/4 IEN-116 Server addresses */
		DHCPOPT_NAME_SERVERS = 5,
		/** N/4 DNS Server addresses */
		DHCPOPT_DOMAIN_NAME_SERVERS = 6,
		/** N/4 Logging Server addresses */
		DHCPOPT_LOG_SERVERS = 7,
		/** N/4 Quotes Server addresses */
		DHCPOPT_QUOTES_SERVERS = 8,
		/** N/4 Quotes Server addresses */
		DHCPOPT_LPR_SERVERS = 9,
		/** N/4 Quotes Server addresses */
		DHCPOPT_IMPRESS_SERVERS = 10,
		/** N/4 RLP Server addresses */
		DHCPOPT_RESOURCE_LOCATION_SERVERS = 11,
		/** Hostname string */
		DHCPOPT_HOST_NAME = 12,
		/** Size of boot file in 512 byte chunks */
		DHCPOPT_BOOT_SIZE = 13,
		/** Client to dump and name the file to dump it to */
		DHCPOPT_MERIT_DUMP = 14,
		/** The DNS domain name of the client */
		DHCPOPT_DOMAIN_NAME = 15,
		/** Swap Server address */
		DHCPOPT_SWAP_SERVER = 16,
		/** Path name for root disk */
		DHCPOPT_ROOT_PATH = 17,
		/** Path name for more BOOTP info */
		DHCPOPT_EXTENSIONS_PATH = 18,
		/** Enable/Disable IP Forwarding */
		DHCPOPT_IP_FORWARDING = 19,
		/** Enable/Disable Source Routing */
		DHCPOPT_NON_LOCAL_SOURCE_ROUTING = 20,
		/** Routing Policy Filters */
		DHCPOPT_POLICY_FILTER = 21,
		/** Max Datagram Reassembly Size */
		DHCPOPT_MAX_DGRAM_REASSEMBLY = 22,
		/** Default IP Time to Live */
		DEFAULT_IP_TTL = 23,
		/** Path MTU Aging Timeout */
		DHCPOPT_PATH_MTU_AGING_TIMEOUT = 24,
		/** Path MTU Plateau Table */
		PATH_MTU_PLATEAU_TABLE = 25,
		/** Interface MTU Size */
		DHCPOPT_INTERFACE_MTU = 26,
		/** All Subnets are Local */
		DHCPOPT_ALL_SUBNETS_LOCAL = 27,
		/** Broadcast Address */
		DHCPOPT_BROADCAST_ADDRESS = 28,
		/** Perform Mask Discovery */
		DHCPOPT_PERFORM_MASK_DISCOVERY = 29,
		/** Provide Mask to Others */
		DHCPOPT_MASK_SUPPLIER = 30,
		/** Perform Router Discovery */
		DHCPOPT_ROUTER_DISCOVERY = 31,
		/** Router Solicitation Address */
		DHCPOPT_ROUTER_SOLICITATION_ADDRESS = 32,
		/** Static Routing Table */
		DHCPOPT_STATIC_ROUTES = 33,
		/** Trailer Encapsulation */
		DHCPOPT_TRAILER_ENCAPSULATION = 34,
		/** ARP Cache Timeout */
		DHCPOPT_ARP_CACHE_TIMEOUT = 35,
		/** IEEE802.3 Encapsulation */
		DHCPOPT_IEEE802_3_ENCAPSULATION = 36,
		/** Default TCP Time to Live */
		DHCPOPT_DEFAULT_TCP_TTL = 37,
		/** TCP Keepalive Interval */
		DHCPOPT_TCP_KEEPALIVE_INTERVAL = 38,
		/** TCP Keepalive Garbage */
		DHCPOPT_TCP_KEEPALIVE_GARBAGE = 39,
		/** NIS Domain Name */
		DHCPOPT_NIS_DOMAIN = 40,
		/** NIS Server Addresses */
		DHCPOPT_NIS_SERVERS = 41,
		/** NTP Server Addresses */
		DHCPOPT_NTP_SERVERS = 42,
		/** Vendor Specific Information */
		DHCPOPT_VENDOR_ENCAPSULATED_OPTIONS = 43,
		/** NETBIOS Name Servers */
		DHCPOPT_NETBIOS_NAME_SERVERS = 44,
		/** NETBIOS Datagram Distribution */
		DHCPOPT_NETBIOS_DD_SERVER = 45,
		/** NETBIOS Node Type */
		DHCPOPT_NETBIOS_NODE_TYPE = 46,
		/** NETBIOS Scope */
		DHCPOPT_NETBIOS_SCOPE = 47,
		/** X Window Font Server */
		DHCPOPT_FONT_SERVERS = 48,
		/** X Window Display Manager */
		DHCPOPT_X_DISPLAY_MANAGER = 49,
		/** Requested IP Address */
		DHCPOPT_DHCP_REQUESTED_ADDRESS = 50,
		/** IP Address Lease Time */
		DHCPOPT_DHCP_LEASE_TIME = 51,
		/** Overload "sname" or "file" */
		DHCPOPT_DHCP_OPTION_OVERLOAD = 52,
		/** DHCP Message Type */
		DHCPOPT_DHCP_MESSAGE_TYPE = 53,
		/** DHCP Server Identification */
		DHCPOPT_DHCP_SERVER_IDENTIFIER = 54,
		/** Parameter Request List */
		DHCPOPT_DHCP_PARAMETER_REQUEST_LIST = 55,
		/** DHCP Error Message */
		DHCPOPT_DHCP_MESSAGE = 56,
		/** DHCP Maximum Message Size */
		DHCPOPT_DHCP_MAX_MESSAGE_SIZE = 57,
		/** DHCP Renewal (T1) Time */
		DHCPOPT_DHCP_RENEWAL_TIME = 58,
		/** DHCP Rebinding (T2) Time */
		DHCPOPT_DHCP_REBINDING_TIME = 59,
		/** Class Identifier */
		DHCPOPT_VENDOR_CLASS_IDENTIFIER = 60,
		/** Class Identifier */
		DHCPOPT_DHCP_CLIENT_IDENTIFIER = 61,
		/** NetWare/IP Domain Name */
		DHCPOPT_NWIP_DOMAIN_NAME = 62,
		/** NetWare/IP sub Options */
		DHCPOPT_NWIP_SUBOPTIONS = 63,
		/** NIS+ v3 Client Domain Name */
		DHCPOPT_NIS_DOMAIN_NAME = 64,
		/** NIS+ v3 Server Addresses */
		DHCPOPT_NIS_SERVER_ADDRESS = 65,
		/** TFTP Server Name */
		DHCPOPT_TFTP_SERVER_NAME = 66,
		/** Boot File Name */
		DHCPOPT_BOOTFILE_NAME = 67,
		/** Home Agent Addresses */
		DHCPOPT_HOME_AGENT_ADDRESS = 68,
		/** Simple Mail Server (SMTP) Addresses */
		DHCPOPT_SMTP_SERVER = 69,
		/** Post Office (POP3) Server Addresses */
		DHCPOPT_POP3_SERVER = 70,
		/** Network News (NNTP) Server Addresses */
		DHCPOPT_NNTP_SERVER = 71,
		/** WWW Server Addresses */
		DHCPOPT_WWW_SERVER = 72,
		/** Finger Server Addresses */
		DHCPOPT_FINGER_SERVER = 73,
		/** Chat (IRC) Server Addresses */
		DHCPOPT_IRC_SERVER = 74,
		/** StreetTalk Server Addresses */
		DHCPOPT_STREETTALK_SERVER = 75,
		/** ST Directory Assist. Addresses */
		DHCPOPT_STDA_SERVER = 76,
		/** User Class Information */
		DHCPOPT_USER_CLASS = 77,
		/** Directory Agent Information */
		DHCPOPT_DIRECTORY_AGENT = 78,
		/** Service Location Agent Scope */
		DHCPOPT_SERVICE_SCOPE = 79,
		/** Rapid Commit */
		DHCPOPT_RAPID_COMMIT = 80,
		/** Fully Qualified Domain Name */
		DHCPOPT_FQDN = 81,
		/** Relay Agent Information */
		DHCPOPT_DHCP_AGENT_OPTIONS = 82,
		/** Internet Storage Name Service */
		DHCPOPT_ISNS = 83,
		/** Novell Directory Services */
		DHCPOPT_NDS_SERVERS = 85,
		/** Novell Directory Services */
		DHCPOPT_NDS_TREE_NAME = 86,
		/** Novell Directory Services */
		DHCPOPT_NDS_CONTEXT = 87,
		/** BCMCS Controller Domain Name list */
		DHCPOPT_BCMCS_CONTROLLER_DOMAIN_NAME_LIST = 88,
		/** BCMCS Controller IPv4 address option */
		DHCPOPT_BCMCS_CONTROLLER_IPV4_ADDRESS = 89,
		/** Authentication */
		DHCPOPT_AUTHENTICATION = 90,
		/** Client Last Transaction Time */
		DHCPOPT_CLIENT_LAST_TXN_TIME = 91,
		/** Associated IP */
		DHCPOPT_ASSOCIATED_IP = 92,
		/** Client System Architecture */
		DHCPOPT_CLIENT_SYSTEM = 93,
		/** Client Network Device Interface */
		DHCPOPT_CLIENT_NDI = 94,
		/** Lightweight Directory Access Protocol [ */
		DHCPOPT_LDAP = 95,
		/** UUID/GUID-based Client Identifier */
		DHCPOPT_UUID_GUID = 97,
		/** Open Group's User Authentication */
		DHCPOPT_USER_AUTH = 98,
		/** GEOCONF_CIVIC */
		DHCPOPT_GEOCONF_CIVIC = 99,
		/** IEEE 1003.1 TZ String */
		DHCPOPT_PCODE = 100,
		/** Reference to the TZ Database */
		DHCPOPT_TCODE = 101,
		/** NetInfo Parent Server Address */
		DHCPOPT_NETINFO_ADDRESS = 112,
		/** NetInfo Parent Server Tag */
		DHCPOPT_NETINFO_TAG = 113,
		/** URL */
		DHCPOPT_URL = 114,
		/** DHCP Auto-Configuration */
		DHCPOPT_AUTO_CONFIG = 116,
		/** Name Service Search */
		DHCPOPT_NAME_SERVICE_SEARCH = 117,
		/** Subnet Selection Option */
		DHCPOPT_SUBNET_SELECTION = 118,
		/** DNS Domain Search List */
		DHCPOPT_DOMAIN_SEARCH = 119,
		/** SIP Servers DHCP Option */
		DHCPOPT_SIP_SERVERS = 120,
		/** Classless Static Route Option */
		DHCPOPT_CLASSLESS_STATIC_ROUTE = 121,
		/** CableLabs Client Configuration */
		DHCPOPT_CCC = 122,
		/** GeoConf Option */
		DHCPOPT_GEOCONF = 123,
		/** Vendor-Identifying Vendor Class */
		DHCPOPT_V_I_VENDOR_CLASS = 124,
		/** Vendor-Identifying Vendor-Specific Information */
		DHCPOPT_V_I_VENDOR_OPTS = 125,
		/** OPTION_PANA_AGENT */
		DHCPOPT_OPTION_PANA_AGENT = 136,
		/** OPTION_V4_LOST */
		DHCPOPT_OPTION_V4_LOST = 137,
		/** CAPWAP Access Controller addresses */
		DHCPOPT_OPTION_CAPWAP_AC_V4 = 138,
		/** A Series Of Suboptions */
		DHCPOPT_OPTION_IPV4_ADDRESS_MOS = 139,
		/** A Series Of Suboptions */
		DHCPOPT_OPTION_IPV4_FQDN_MOS = 140,
		/** List of domain names to search for SIP User Agent Configuration */
		DHCPOPT_SIP_UA_CONFIG = 141,
		/** ANDSF IPv4 Address Option for DHCPv4 */
		DHCPOPT_OPTION_IPV4_ADDRESS_ANDSF = 142,
		/** Geospatial Location with Uncertainty [RF */
		DHCPOPT_GEOLOC = 144,
		/** Forcerenew Nonce Capable */
		DHCPOPT_FORCERENEW_NONCE_CAPABLE = 145,
		/** Information for selecting RDNSS */
		DHCPOPT_RDNSS_SELECTION = 146,
		/** Status code and optional N byte text message describing status */
		DHCPOPT_STATUS_CODE = 151,
		/** Absolute time (seconds since Jan 1, 1970) message was sent */
		DHCPOPT_BASE_TIME = 152,
		/** Number of seconds in the past when client entered current state */
		DHCPOPT_START_TIME_OF_STATE = 153,
		/** Absolute time (seconds since Jan 1, 1970) for beginning of query */
		DHCPOPT_QUERY_START_TIME = 154,
		/** Absolute time (seconds since Jan 1, 1970) for end of query */
		DHCPOPT_QUERY_END_TIME = 155,
		/** State of IP address */
		DHCPOPT_DHCP_STATE = 156,
		/** Indicates information came from local or remote server */
		DHCPOPT_DATA_SOURCE = 157,
		/** Includes one or multiple lists of PCP server IP addresses; each list is treated as a separate PCP server */
		DHCPOPT_OPTION_V4_PCP_SERVER = 158,
		/** This option is used to configure a set of ports bound to a shared IPv4 address */
		DHCPOPT_OPTION_V4_PORTPARAMS = 159,
		/** DHCP Captive-Portal */
		DHCPOPT_CAPTIVE_PORTAL = 160,
		/** Manufacturer Usage Descriptions */
		DHCPOPT_OPTION_MUD_URL_V4 = 161,
		/** Etherboot */
		DHCPOPT_ETHERBOOT = 175,
		/** IP Telephone */
		DHCPOPT_IP_TELEPHONE = 176,
		/** Magic string = F1:00:74:7E */
		DHCPOPT_PXELINUX_MAGIC = 208,
		/** Configuration file */
		DHCPOPT_CONFIGURATION_FILE = 209,
		/** Path Prefix Option */
		DHCPOPT_PATH_PREFIX = 210,
		/** Reboot Time */
		DHCPOPT_REBOOT_TIME = 211,
		/** OPTION_6RD with N/4 6rd BR addresses */
		DHCPOPT_OPTION_6RD = 212,
		/** Access Network Domain Name */
		DHCPOPT_OPTION_V4_ACCESS_DOMAIN = 213,
		/** Subnet Allocation Option */
		DHCPOPT_SUBNET_ALLOCATION = 220,
		/** Virtual Subnet Selection (VSS) Option */
		DHCPOPT_VIRTUAL_SUBNET_SELECTION = 221,
		/** End (last option) */
		DHCPOPT_END = 255
	};

	/**
	 * @class DhcpOption
	 * A wrapper class for DHCP options. This class does not create or modify DHCP option records, but rather
	 * serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	 */
	class DhcpOption : public TLVRecord<uint8_t, uint8_t>
	{
	public:
		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the option raw data
		 */
		explicit DhcpOption(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		virtual ~DhcpOption()
		{}

		/**
		 * Retrieve DHCP option data as IPv4 address. Relevant only if option value is indeed an IPv4 address
		 * @return DHCP option data as IPv4 address
		 */
		IPv4Address getValueAsIpAddr() const
		{
			return getValueAs<uint32_t>();
		}

		/**
		 * Set DHCP option data as IPv4 address. This method copies the 4 bytes of the IP address to the option value
		 * @param[in] addr The IPv4 address to set
		 * @param[in] valueOffset An optional parameter that specifies where to start set the option data (default set
		 * to 0). For example: if option data is 20 bytes long and you want to set the IP address in the 4 last bytes
		 * then use this method like this: setValueIpAddr(your_addr, 16)
		 */
		void setValueIpAddr(const IPv4Address& addr, int valueOffset = 0)
		{
			setValue<uint32_t>(addr.toInt(), valueOffset);
		}

		/**
		 * Retrieve DHCP option data as string. Relevant only if option value is indeed a string
		 * @param[in] valueOffset An optional parameter that specifies where to start copy the DHCP option data. For
		 * example: when retrieving Client FQDN option, you may ignore the flags and RCODE fields using this method like
		 * this: getValueAsString(3). The default is 0 - start copying from the beginning of option data
		 * @return DHCP option data as string
		 */
		std::string getValueAsString(int valueOffset = 0) const
		{
			if (m_Data == nullptr || m_Data->recordLen - valueOffset < 1)
				return "";

			return std::string((const char*)m_Data->recordValue + valueOffset, (int)m_Data->recordLen - valueOffset);
		}

		/**
		 * Set DHCP option data as string. This method copies the string to the option value. If the string is longer
		 * than option length the string is trimmed so it will fit the option length
		 * @param[in] stringValue The string to set
		 * @param[in] valueOffset An optional parameter that specifies where to start set the option data (default set
		 * to 0). For example: if option data is 20 bytes long and you want to set a 6 char-long string in the 6 last
		 * bytes then use this method like this: setValueString("string", 14)
		 */
		void setValueString(const std::string& stringValue, int valueOffset = 0)
		{
			// calculate the maximum length of the destination buffer
			size_t len = (size_t)m_Data->recordLen - (size_t)valueOffset;

			// use the length of input string if a buffer is large enough for whole string
			if (stringValue.length() < len)
				len = stringValue.length();

			memcpy(m_Data->recordValue + valueOffset, stringValue.data(), len);
		}

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

			if (data->recordType == (uint8_t)DHCPOPT_END || data->recordType == (uint8_t)DHCPOPT_PAD)
				return true;

			return TLVRecord<uint8_t, uint8_t>::canAssign(recordRawData, tlvDataLen);
		}

		// implement abstract methods

		size_t getTotalSize() const
		{
			if (m_Data == nullptr)
				return 0;

			if (m_Data->recordType == (uint8_t)DHCPOPT_END || m_Data->recordType == (uint8_t)DHCPOPT_PAD)
				return sizeof(uint8_t);

			return sizeof(uint8_t) * 2 + (size_t)m_Data->recordLen;
		}

		size_t getDataSize() const
		{
			if (m_Data == nullptr)
				return 0;

			if (m_Data->recordType == (uint8_t)DHCPOPT_END || m_Data->recordType == (uint8_t)DHCPOPT_PAD)
				return 0;

			return m_Data->recordLen;
		}
	};

	/**
	 * @class DhcpOptionBuilder
	 * A class for building DHCP options. This builder receives the option parameters in its c'tor,
	 * builds the DHCP option raw buffer and provides a build() method to get a DhcpOption object out of it
	 */
	class DhcpOptionBuilder : public TLVRecordBuilder
	{
	public:
		/**
		 * A c'tor for building DHCP options which their value is a byte array. The DhcpOption object can later
		 * be retrieved by calling build()
		 * @param[in] optionType DHCP option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		 * any way
		 * @param[in] optionValueLen DHCP option value length in bytes
		 */
		DhcpOptionBuilder(DhcpOptionTypes optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue, optionValueLen)
		{}

		/**
		 * A c'tor for building DHCP options which have a 1-byte value. The DhcpOption object can later be retrieved
		 * by calling build()
		 * @param[in] optionType DHCP option type
		 * @param[in] optionValue A 1-byte option value
		 */
		DhcpOptionBuilder(DhcpOptionTypes optionType, uint8_t optionValue)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue)
		{}

		/**
		 * A c'tor for building DHCP options which have a 2-byte value. The DhcpOption object can later be retrieved
		 * by calling build()
		 * @param[in] optionType DHCP option type
		 * @param[in] optionValue A 2-byte option value
		 */
		DhcpOptionBuilder(DhcpOptionTypes optionType, uint16_t optionValue)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue)
		{}

		/**
		 * A c'tor for building DHCP options which have a 4-byte value. The DhcpOption object can later be retrieved
		 * by calling build()
		 * @param[in] optionType DHCP option type
		 * @param[in] optionValue A 4-byte option value
		 */
		DhcpOptionBuilder(DhcpOptionTypes optionType, uint32_t optionValue)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue)
		{}

		/**
		 * A c'tor for building DHCP options which have an IPv4Address value. The DhcpOption object can later be
		 * retrieved by calling build()
		 * @param[in] optionType DHCP option type
		 * @param[in] optionValue The IPv4 address option value
		 */
		DhcpOptionBuilder(DhcpOptionTypes optionType, const IPv4Address& optionValue)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue)
		{}

		/**
		 * A c'tor for building DHCP options which have a string value. The DhcpOption object can later be retrieved
		 * by calling build()
		 * @param[in] optionType DHCP option type
		 * @param[in] optionValue The string option value
		 */
		DhcpOptionBuilder(DhcpOptionTypes optionType, const std::string& optionValue)
		    : TLVRecordBuilder((uint8_t)optionType, optionValue)
		{}

		/**
		 * A copy c'tor which copies all the data from another instance of DhcpOptionBuilder
		 * @param[in] other The instance to copy from
		 */
		DhcpOptionBuilder(const DhcpOptionBuilder& other) : TLVRecordBuilder(other)
		{}

		/**
		 * Assignment operator that copies all data from another instance of DhcpOptionBuilder
		 * @param[in] other The instance to assign from
		 * @return A reference to the assignee
		 */
		DhcpOptionBuilder& operator=(const DhcpOptionBuilder& other)
		{
			TLVRecordBuilder::operator=(other);
			return *this;
		}

		/**
		 * Build the DhcpOption object out of the parameters defined in the c'tor
		 * @return The DhcpOption object
		 */
		DhcpOption build() const;
	};

	/**
	 * @class DhcpLayer
	 * Represents a DHCP (Dynamic Host Configuration Protocol) protocol layer
	 */
	class DhcpLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DhcpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates the layer from scratch. Adds a ::DHCPOPT_DHCP_MESSAGE_TYPE and a ::DHCPOPT_END
		 * options
		 * @param[in] msgType A DHCP message type to be set
		 * @param[in] clientMacAddr A client MAC address to set in dhcp_header#clientHardwareAddress field
		 */
		DhcpLayer(DhcpMessageType msgType, const MacAddress& clientMacAddr);

		/**
		 * A constructor that creates the layer from scratch with clean data
		 */
		DhcpLayer();

		/**
		 * A destructor for this layer
		 */
		virtual ~DhcpLayer()
		{}

		/**
		 * Get a pointer to the DHCP header. Notice this points directly to the data, so every change will change the
		 * actual packet data
		 * @return A pointer to the @ref dhcp_header
		 */
		dhcp_header* getDhcpHeader() const
		{
			return (dhcp_header*)m_Data;
		}

		/**
		 * @return The BootP opcode of this message
		 */
		BootpOpCodes getOpCode() const
		{
			return (BootpOpCodes)getDhcpHeader()->opCode;
		}

		/**
		 * @return The client IPv4 address (as extracted from dhcp_header#clientIpAddress converted to IPv4Address
		 * object)
		 */
		IPv4Address getClientIpAddress() const
		{
			return getDhcpHeader()->clientIpAddress;
		}

		/**
		 * Set the client IPv4 address in dhcp_header#clientIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setClientIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->clientIpAddress = addr.toInt();
		}

		/**
		 * @return The server IPv4 address (as extracted from dhcp_header#serverIpAddress converted to IPv4Address
		 * object)
		 */
		IPv4Address getServerIpAddress() const
		{
			return getDhcpHeader()->serverIpAddress;
		}

		/**
		 * Set the server IPv4 address in dhcp_header#serverIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setServerIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->serverIpAddress = addr.toInt();
		}

		/**
		 * @return Your IPv4 address (as extracted from dhcp_header#yourIpAddress converted to IPv4Address object)
		 */
		IPv4Address getYourIpAddress() const
		{
			return getDhcpHeader()->yourIpAddress;
		}

		/**
		 * Set your IPv4 address in dhcp_header#yourIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setYourIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->yourIpAddress = addr.toInt();
		}

		/**
		 * @return Gateway IPv4 address (as extracted from dhcp_header#gatewayIpAddress converted to IPv4Address object)
		 */
		IPv4Address getGatewayIpAddress() const
		{
			return getDhcpHeader()->gatewayIpAddress;
		}

		/**
		 * Set the gateway IPv4 address in dhcp_header#gatewayIpAddress
		 * @param[in] addr The IPv4 address to set
		 */
		void setGatewayIpAddress(const IPv4Address& addr)
		{
			getDhcpHeader()->gatewayIpAddress = addr.toInt();
		}

		/**
		 * @return The client MAC address as extracted from dhcp_header#clientHardwareAddress, assuming
		 * dhcp_header#hardwareType is 1 (Ethernet) and dhcp_header#hardwareAddressLength is 6 (MAC address length).
		 * Otherwise returns MacAddress#Zero
		 */
		MacAddress getClientHardwareAddress() const;

		/**
		 * Set a MAC address into the first 6 bytes of dhcp_header#clientHardwareAddress. This method also sets
		 * dhcp_header#hardwareType to 1 (Ethernet) and dhcp_header#hardwareAddressLength to 6 (MAC address length)
		 * @param[in] addr The MAC address to set
		 */
		void setClientHardwareAddress(const MacAddress& addr);

		/**
		 * @return DHCP message type as extracted from ::DHCPOPT_DHCP_MESSAGE_TYPE option. If this option doesn't exist
		 * the value of
		 * ::DHCP_UNKNOWN_MSG_TYPE is returned
		 */
		DhcpMessageType getMessageType() const;

		/**
		 * Set DHCP message type. This method searches for existing ::DHCPOPT_DHCP_MESSAGE_TYPE option. If found, it
		 * sets the requested message type as its value. If not, it creates a ::DHCPOPT_DHCP_MESSAGE_TYPE option and
		 * sets the requested message type as its value
		 * @param[in] msgType Message type to set
		 * @return True if message type was set successfully or false if msgType is ::DHCP_UNKNOWN_MSG_TYPE or if failed
		 * to add
		 * ::DHCPOPT_DHCP_MESSAGE_TYPE option
		 */
		bool setMessageType(DhcpMessageType msgType);

		/**
		 * @return The first DHCP option in the packet. If there are no DHCP options the returned value will contain
		 * a logical null (DhcpOption#isNull() == true)
		 */
		DhcpOption getFirstOptionData() const;

		/**
		 * Get the DHCP option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical null (DhcpOption#isNull() == true)
		 * @param[in] dhcpOption A given DHCP option
		 * @return A DhcpOption object containing the option data that comes next, or logical null if the given DHCP
		 * option: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		 */
		DhcpOption getNextOptionData(DhcpOption dhcpOption) const;

		/**
		 * Get a DHCP option by type
		 * @param[in] option DHCP option type
		 * @return A DhcpOption object containing the first DHCP option data that matches this type, or logical null
		 * (DhcpOption#isNull() == true) if no such option found
		 */
		DhcpOption getOptionData(DhcpOptionTypes option) const;

		/**
		 * @return The number of DHCP options in this layer
		 */
		size_t getOptionsCount() const;

		/**
		 * Add a new DHCP option at the end of the layer
		 * @param[in] optionBuilder A DhcpOptionBuilder object that contains the requested DHCP option data to add
		 * @return A DhcpOption object containing the newly added DHCP option data or logical null
		 * (DhcpOption#isNull() == true) if addition failed
		 */
		DhcpOption addOption(const DhcpOptionBuilder& optionBuilder);

		/**
		 * Add a new DHCP option after an existing one
		 * @param[in] optionBuilder A DhcpOptionBuilder object that contains the requested DHCP option data to add
		 * @param[in] prevOption The DHCP option type which the newly added option will come after
		 * @return A DhcpOption object containing the newly added DHCP option data or logical null
		 * (DhcpOption#isNull() == true) if addition failed
		 */
		DhcpOption addOptionAfter(const DhcpOptionBuilder& optionBuilder, DhcpOptionTypes prevOption);

		/**
		 * Remove an existing DHCP option from the layer
		 * @param[in] optionType The DHCP option type to remove
		 * @return True if DHCP option was successfully removed or false if type wasn't found or if removal failed
		 */
		bool removeOption(DhcpOptionTypes optionType);

		/**
		 * Remove all DHCP options in this layer
		 * @return True if all DHCP options were successfully removed or false if removal failed for some reason
		 */
		bool removeAllOptions();

		/**
		 * A static method that checks whether a pair of ports are considered DHCP ports
		 * @param[in] portSrc The source port number to check
		 * @param[in] portDst The destination port number to check
		 * @return True if these are DHCP port numbers, false otherwise
		 */
		static inline bool isDhcpPorts(uint16_t portSrc, uint16_t portDst);

		// implement abstract methods

		/**
		 * Does nothing for this layer (DhcpLayer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return The size of @ref dhcp_header + size of options
		 */
		size_t getHeaderLen() const
		{
			return m_DataLen;
		}

		/**
		 * Calculate the following fields:
		 * - @ref dhcp_header#magicNumber = DHCP magic number (0x63538263)
		 * - @ref dhcp_header#opCode = ::DHCP_BOOTREQUEST for message types: ::DHCP_DISCOVER, ::DHCP_REQUEST,
		 * ::DHCP_DECLINE, ::DHCP_RELEASE,
		 *                            ::DHCP_INFORM, ::DHCP_UNKNOWN_MSG_TYPE
		 *                            ::DHCP_BOOTREPLY for message types: ::DHCP_OFFER, ::DHCP_ACK, ::DHCP_NAK
		 * - @ref dhcp_header#hardwareType = 1 (Ethernet)
		 * - @ref dhcp_header#hardwareAddressLength = 6 (MAC address length)
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const
		{
			return OsiModelApplicationLayer;
		}

	private:
		uint8_t* getOptionsBasePtr() const
		{
			return m_Data + sizeof(dhcp_header);
		}

		TLVRecordReader<DhcpOption> m_OptionReader;

		void initDhcpLayer(size_t numOfBytesToAllocate);

		DhcpOption addOptionAt(const DhcpOptionBuilder& optionBuilder, int offset);
	};

	// implementation of inline methods

	bool DhcpLayer::isDhcpPorts(uint16_t portSrc, uint16_t portDst)
	{
		return ((portSrc == 68 && portDst == 67) || (portSrc == 67 && portDst == 68) ||
		        (portSrc == 67 && portDst == 67));
	}

}  // namespace vanhooks::net
// ---- end DhcpLayer.h ----

// ---- begin DhcpV6Layer.h ----
/// @file

/**
 * \namespace vanhooks::net
 * \brief The main namespace for the VanHooks lib
 */
namespace vanhooks::net
{
	/**
	 * DHCPv6 message types
	 */
	enum DhcpV6MessageType
	{
		/** Unknown message type */
		DHCPV6_UNKNOWN_MSG_TYPE = 0,
		/** Solicit message type (Client to Server) */
		DHCPV6_SOLICIT = 1,
		/** Advertise message type (Server to Client) */
		DHCPV6_ADVERTISE = 2,
		/** Request message type (Client to Server) */
		DHCPV6_REQUEST = 3,
		/** Confirm message type (Client to Server) */
		DHCPV6_CONFIRM = 4,
		/** Renew message type (Client to Server) */
		DHCPV6_RENEW = 5,
		/** Rebind message type (Client to Server) */
		DHCPV6_REBIND = 6,
		/** Reply message type (Server to Client) */
		DHCPV6_REPLY = 7,
		/** Release message type (Client to Server) */
		DHCPV6_RELEASE = 8,
		/** Decline message type (Client to Server) */
		DHCPV6_DECLINE = 9,
		/** Reconfigure message type (Server to Client) */
		DHCPV6_RECONFIGURE = 10,
		/** Information-Request message type (Client to Server) */
		DHCPV6_INFORMATION_REQUEST = 11,
		/** Relay-Forward message type (Relay agent to Server) */
		DHCPV6_RELAY_FORWARD = 12,
		/** Relay-Reply message type (Server to Relay agent) */
		DHCPV6_RELAY_REPLY = 13
	};

	/**
	 * DHCPv6 option types.
	 * Resources for more information:
	 * - https://onlinelibrary.wiley.com/doi/pdf/10.1002/9781118073810.app2
	 * - https://datatracker.ietf.org/doc/html/rfc5970
	 * - https://datatracker.ietf.org/doc/html/rfc6607
	 * - https://datatracker.ietf.org/doc/html/rfc8520
	 */
	enum DhcpV6OptionType
	{
		/** Unknown option type */
		DHCPV6_OPT_UNKNOWN = 0,
		/** Client Identifier (DUID of client) */
		DHCPV6_OPT_CLIENTID = 1,
		/** Server Identifier (DUID of server) */
		DHCPV6_OPT_SERVERID = 2,
		/** Identity Association for Non-temporary addresses */
		DHCPV6_OPT_IA_NA = 3,
		/** Identity Association for Temporary addresses */
		DHCPV6_OPT_IA_TA = 4,
		/** IA Address option */
		DHCPV6_OPT_IAADDR = 5,
		/** Option Request Option */
		DHCPV6_OPT_ORO = 6,
		/** Preference setting */
		DHCPV6_OPT_PREFERENCE = 7,
		/** The amount of time since the client began the current DHCP transaction */
		DHCPV6_OPT_ELAPSED_TIME = 8,
		/** The DHCP message being relayed by a relay agent */
		DHCPV6_OPT_RELAY_MSG = 9,
		/** Authentication  information */
		DHCPV6_OPT_AUTH = 11,
		/** Server unicast */
		DHCPV6_OPT_UNICAST = 12,
		/** Status code */
		DHCPV6_OPT_STATUS_CODE = 13,
		/** Rapid commit */
		DHCPV6_OPT_RAPID_COMMIT = 14,
		/** User class */
		DHCPV6_OPT_USER_CLASS = 15,
		/** Vendor class */
		DHCPV6_OPT_VENDOR_CLASS = 16,
		/** Vendor specific information */
		DHCPV6_OPT_VENDOR_OPTS = 17,
		/** Interface ID */
		DHCPV6_OPT_INTERFACE_ID = 18,
		/** Reconfigure Message */
		DHCPV6_OPT_RECONF_MSG = 19,
		/** Reconfigure Accept */
		DHCPV6_OPT_RECONF_ACCEPT = 20,
		/** SIP Servers Domain Name */
		DHCPV6_OPT_SIP_SERVERS_D = 21,
		/** SIP Servers IPv6 Address List */
		DHCPV6_OPT_SIP_SERVERS_A = 22,
		/** DNS Recursive Name Server */
		DHCPV6_OPT_DNS_SERVERS = 23,
		/** Domain Search List */
		DHCPV6_OPT_DOMAIN_LIST = 24,
		/** Identity Association for Prefix Delegation */
		DHCPV6_OPT_IA_PD = 25,
		/** IA_PD Prefix */
		DHCPV6_OPT_IAPREFIX = 26,
		/** Network Information Service (NIS) Servers */
		DHCPV6_OPT_NIS_SERVERS = 27,
		/** Network Information Service v2 (NIS+) Servers */
		DHCPV6_OPT_NISP_SERVERS = 28,
		/** Network Information Service (NIS) domain name */
		DHCPV6_OPT_NIS_DOMAIN_NAME = 29,
		/** Network Information Service v2 (NIS+) domain name */
		DHCPV6_OPT_NISP_DOMAIN_NAME = 30,
		/** Simple Network Time Protocol (SNTP) servers */
		DHCPV6_OPT_SNTP_SERVERS = 31,
		/** Information Refresh */
		DHCPV6_OPT_INFORMATION_REFRESH_TIME = 32,
		/** Broadcast and Multicast Service (BCMCS) Domain Name List */
		DHCPV6_OPT_BCMCS_SERVER_D = 33,
		/** Broadcast and Multicast Service (BCMCS) IPv6 Address List */
		DHCPV6_OPT_BCMCS_SERVER_A = 34,
		/** Geographical location in civic (e.g., postal) format */
		DHCPV6_OPT_GEOCONF_CIVIC = 36,
		/** Relay Agent Remote ID */
		DHCPV6_OPT_REMOTE_ID = 37,
		/** Relay Agent Subscriber ID */
		DHCPV6_OPT_SUBSCRIBER_ID = 38,
		/** FQDN */
		DHCPV6_OPT_CLIENT_FQDN = 39,
		/** One or more IPv6 addresses associated with PANA (Protocol for carrying Authentication for Network Access)
		 * Authentication Agents */
		DHCPV6_OPT_PANA_AGENT = 40,
		/** Time zone to be used by the client in IEEE 1003.1 format */
		DHCPV6_OPT_NEW_POSIX_TIMEZONE = 41,
		/** Time zone (TZ) database entry referred to by entry name */
		DHCPV6_OPT_NEW_TZDB_TIMEZONE = 42,
		/** Relay Agent Echo Request */
		DHCPV6_OPT_ERO = 43,
		/** Query option */
		DHCPV6_OPT_LQ_QUERY = 44,
		/** Client Data */
		DHCPV6_OPT_CLIENT_DATA = 45,
		/** Client Last Transaction Time */
		DHCPV6_OPT_CLT_TIME = 46,
		/** Relay data */
		DHCPV6_OPT_LQ_RELAY_DATA = 47,
		/** Client link */
		DHCPV6_OPT_LQ_CLIENT_LINK = 48,
		/** Mobile IPv6 Home Network Information */
		DHCPV6_OPT_MIP6_HNINF = 49,
		/** Mobile IPv6 Relay Agent */
		DHCPV6_OPT_MIP6_RELAY = 50,
		/** Location to Service Translation (LoST) server domain name */
		DHCPV6_OPT_V6_LOST = 51,
		/** Access Points (CAPWAP) Access Controller IPv6 addresses */
		DHCPV6_OPT_CAPWAP_AC_V6 = 52,
		/** DHCPv6 Bulk LeaseQuery */
		DHCPV6_OPT_RELAY_ID = 53,
		/** List of IPv6 addresses for servers providing particular types of IEEE 802.21 Mobility Service (MoS) */
		DHCPV6_OPT_IPH6_ADDRESS_MOS = 54,
		/** List of FQDNs for servers providing particular types of IEEE 802.21 Mobility Service (MoS) */
		DHCPV6_OPT_IPV6_FQDN_MOS = 55,
		/** Network Time Protocol (NTP) or Simple NTP (SNTP) Server Location */
		DHCPV6_OPT_NTP_SERVER = 56,
		/** Boot File Uniform Resource Locator (URL) */
		DHCPV6_OPT_BOOTFILE_URL = 59,
		/** Boot File Parameters */
		DHCPV6_OPT_BOOTFILE_PARAM = 60,
		/** Client System Architecture Type */
		DHCPV6_OPT_CLIENT_ARCH_TYPE = 61,
		/** Client Network Interface Identifier */
		DHCPV6_OPT_NII = 62,
		/** ERP Local Domain Name */
		DHCPV6_OPT_ERP_LOCAL_DOMAIN_NAME = 65,
		/** Relay supplied options */
		DHCPV6_OPT_RELAY_SUPPLIED_OPTIONS = 66,
		/** Virtual Subnet Selection */
		DHCPV6_OPT_VSS = 68,
		/** Client link layer */
		DHCPV6_OPT_CLIENT_LINKLAYER_ADDR = 79,
		/** Manufacturer Usage Description */
		DHCPV6_OPT_MUD_URL = 112
	};

	/**
	 * @class DhcpV6Option
	 * A wrapper class for DHCPv6 options. This class does not create or modify DHCP option records, but rather
	 * serves as a wrapper and provides useful methods for setting and retrieving data to/from them
	 */
	class DhcpV6Option : public TLVRecord<uint16_t, uint16_t>
	{
	public:
		/**
		 * A c'tor for this class that gets a pointer to the option raw data (byte array)
		 * @param[in] optionRawData A pointer to the option raw data
		 */
		explicit DhcpV6Option(uint8_t* optionRawData) : TLVRecord(optionRawData)
		{}

		/**
		 * A d'tor for this class, currently does nothing
		 */
		virtual ~DhcpV6Option()
		{}

		/**
		 * @return The option type converted to ::DhcpV6OptionType enum
		 */
		DhcpV6OptionType getType() const;

		/**
		 * @return The raw option value (byte array) as a hex string
		 */
		std::string getValueAsHexString() const;

		// implement abstract methods

		size_t getTotalSize() const;
		size_t getDataSize() const;
	};

	/**
	 * @class DhcpV6OptionBuilder
	 * A class for building DHCPv6 options. This builder receives the option parameters in its c'tor,
	 * builds the DHCPv6 option raw buffer and provides a build() method to get a DhcpV6Option object out of it
	 */
	class DhcpV6OptionBuilder : public TLVRecordBuilder
	{
	public:
		/**
		 * A c'tor for building DHCPv6 options from a string representing the hex stream of the raw byte value.
		 * The DhcpV6Option object can later be retrieved by calling build()
		 * @param[in] optionType DHCPv6 option type
		 * @param[in] optionValueAsHexStream The value as a hex stream string
		 */
		DhcpV6OptionBuilder(DhcpV6OptionType optionType, const std::string& optionValueAsHexStream)
		    : TLVRecordBuilder(static_cast<uint16_t>(optionType), optionValueAsHexStream, true)
		{}

		/**
		 * A c'tor for building DHCPv6 options from a byte array representing their value. The DhcpV6Option object can
		 * be later retrieved by calling build()
		 * @param[in] optionType DHCPv6 option type
		 * @param[in] optionValue A buffer containing the option value. This buffer is read-only and isn't modified in
		 * any way.
		 * @param[in] optionValueLen Option value length in bytes
		 */
		DhcpV6OptionBuilder(DhcpV6OptionType optionType, const uint8_t* optionValue, uint8_t optionValueLen)
		    : TLVRecordBuilder(static_cast<uint16_t>(optionType), optionValue, optionValueLen)
		{}

		/**
		 * Build the DhcpV6Option object out of the parameters defined in the c'tor
		 * @return The DhcpV6Option object
		 */
		DhcpV6Option build() const;
	};

	/**
	 * @struct dhcpv6_header
	 * Represents the basic DHCPv6 protocol header
	 */
	struct dhcpv6_header
	{
		/** DHCPv6 message type */
		uint8_t messageType;
		/** DHCPv6 transaction ID (first byte) */
		uint8_t transactionId1;
		/** DHCPv6 transaction ID (second byte) */
		uint8_t transactionId2;
		/** DHCPv6 transaction ID (last byte) */
		uint8_t transactionId3;
	};

	/**
	 * @class DhcpV6Layer
	 * Represents a DHCPv6 (Dynamic Host Configuration Protocol version 6) protocol layer
	 */
	class DhcpV6Layer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] prevLayer A pointer to the previous layer
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		DhcpV6Layer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet);

		/**
		 * A constructor that creates the layer from scratch
		 * @param[in] messageType A DHCPv6 message type to be set
		 * @param[in] transactionId The transaction ID to be set. Notice the transaction ID is 3-byte long so the value
		 * shouldn't exceed 0xFFFFFF
		 */
		DhcpV6Layer(DhcpV6MessageType messageType, uint32_t transactionId);

		/**
		 * @return The message type of this DHCPv6 message
		 */
		DhcpV6MessageType getMessageType() const;

		/**
		 * @return The string value of the message type of this DHCPv6 message
		 */
		std::string getMessageTypeAsString() const;

		/**
		 * Set the message type for this layer
		 * @param[in] messageType The message type to set
		 */
		void setMessageType(DhcpV6MessageType messageType);

		/**
		 * @return The transaction ID of this DHCPv6 message
		 */
		uint32_t getTransactionID() const;

		/**
		 * Set the transaction ID for this DHCPv6 message
		 * @param[in] transactionId The transaction ID value to set
		 */
		void setTransactionID(uint32_t transactionId) const;

		/**
		 * @return The first DHCPv6 option in the packet. If there are no DHCPv6 options the returned value will contain
		 * a logical null (DhcpV6Option#isNull() == true)
		 */
		DhcpV6Option getFirstOptionData() const;

		/**
		 * Get the DHCPv6 option that comes after a given option. If the given option was the last one, the
		 * returned value will contain a logical null (DhcpV6Option#isNull() == true)
		 * @param[in] dhcpv6Option A given DHCPv6 option
		 * @return A DhcpV6Option object containing the option data that comes next, or logical null if the given
		 * DHCPv6 option: (1) was the last one; (2) contains a logical null or (3) doesn't belong to this packet
		 */
		DhcpV6Option getNextOptionData(DhcpV6Option dhcpv6Option) const;

		/**
		 * Get a DHCPv6 option by type
		 * @param[in] option DHCPv6 option type
		 * @return A DhcpV6OptionType object containing the first DHCP option data that matches this type, or logical
		 * null (DhcpV6Option#isNull() == true) if no such option found
		 */
		DhcpV6Option getOptionData(DhcpV6OptionType option) const;

		/**
		 * @return The number of DHCPv6 options in this layer
		 */
		size_t getOptionCount() const;

		/**
		 * Add a new DHCPv6 option at the end of the layer
		 * @param[in] optionBuilder A DhcpV6OptionBuilder object that contains the requested DHCPv6 option data to add
		 * @return A DhcpV6Option object containing the newly added DHCP option data or logical null
		 * (DhcpV6Option#isNull() == true) if addition failed
		 */
		DhcpV6Option addOption(const DhcpV6OptionBuilder& optionBuilder);

		/**
		 * Add a new DHCPv6 option after an existing one
		 * @param[in] optionBuilder A DhcpV6OptionBuilder object that contains the requested DHCPv6 option data to add
		 * @param[in] optionType The DHCPv6 option type which the newly added option will come after
		 * @return A DhcpV6Option object containing the newly added DHCPv6 option data or logical null
		 * (DhcpV6Option#isNull() == true) if addition failed
		 */
		DhcpV6Option addOptionAfter(const DhcpV6OptionBuilder& optionBuilder, DhcpV6OptionType optionType);

		/**
		 * Add a new DHCPv6 option before an existing one
		 * @param[in] optionBuilder A DhcpV6OptionBuilder object that contains the requested DHCPv6 option data to add
		 * @param[in] optionType The DHCPv6 option type which the newly added option will come before
		 * @return A DhcpV6Option object containing the newly added DHCPv6 option data or logical null
		 * (DhcpV6Option#isNull() == true) if addition failed
		 */
		DhcpV6Option addOptionBefore(const DhcpV6OptionBuilder& optionBuilder, DhcpV6OptionType optionType);

		/**
		 * Remove an existing DHCPv6 option from the layer
		 * @param[in] optionType The DHCPv6 option type to remove
		 * @return True if DHCPv6 option was successfully removed or false if type wasn't found or if removal failed
		 */
		bool removeOption(DhcpV6OptionType optionType);

		/**
		 * Remove all DHCPv6 options in this layer
		 * @return True if all DHCPv6 options were successfully removed or false if removal failed for some reason
		 */
		bool removeAllOptions();

		/**
		 * A static method that checks whether a port is considered as a DHCPv6 port
		 * @param[in] port The port number to check
		 * @return True if this is a DHCPv6 port number, false otherwise
		 */
		static inline bool isDhcpV6Port(uint16_t port);

		/**
		 * A static method that validates the input data
		 * @param[in] data The pointer to the beginning of a byte stream of an DHCPv6 layer
		 * @param[in] dataLen The length of the byte stream
		 * @return True if the data is valid and can represent an DHCPv6 layer
		 */
		static inline bool isDataValid(const uint8_t* data, size_t dataLen);

		// implement abstract methods

		/**
		 * Does nothing for this layer (DhcpV6Layer is always last)
		 */
		void parseNextLayer()
		{}

		/**
		 * @return The size of @ref dhcpv6_header + size of options
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
			return OsiModelApplicationLayer;
		}

	private:
		uint8_t* getOptionsBasePtr() const
		{
			return m_Data + sizeof(dhcpv6_header);
		}
		dhcpv6_header* getDhcpHeader() const
		{
			return (dhcpv6_header*)m_Data;
		}
		DhcpV6Option addOptionAt(const DhcpV6OptionBuilder& optionBuilder, int offset);

		TLVRecordReader<DhcpV6Option> m_OptionReader;
	};

	// implementation of inline methods

	bool DhcpV6Layer::isDhcpV6Port(uint16_t port)
	{
		return (port == 546) || (port == 547);
	}

	bool DhcpV6Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return data && dataLen >= sizeof(dhcpv6_header);
	}

}  // namespace vanhooks::net
// ---- end DhcpV6Layer.h ----

