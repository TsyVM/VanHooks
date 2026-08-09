#pragma once

// Minimal JSON reader.
//
// Replaces a vendored copy of nlohmann::json (~24.6k lines) that was pulled
// in for exactly one consumer, OUILookup::internalParser(), which only ever
// needs: nested objects, arrays, strings, and integers. This file covers
// that surface area (a couple hundred lines) instead of a general-purpose
// JSON library. Not intended as a drop-in replacement for nlohmann::json
// outside of that use case.

#include <cctype>
#include <cstdint>
#include <istream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace vanhooks::net::json
{
	class Value
	{
	public:
		enum class Type
		{
			Null,
			Object,
			Array,
			String,
			Integer,
			Boolean
		};

		Value() = default;

		static Value parse(const std::string& text)
		{
			size_t i = 0;
			return parseValue(text, i);
		}

		static Value parse(std::istream& in)
		{
			std::ostringstream buf;
			buf << in.rdbuf();
			return parse(buf.str());
		}

		Type type() const { return type_; }
		bool is_object() const { return type_ == Type::Object; }
		bool is_array() const { return type_ == Type::Array; }
		bool is_string() const { return type_ == Type::String; }
		bool is_number_integer() const { return type_ == Type::Integer; }

		bool contains(const std::string& key) const
		{
			return type_ == Type::Object && object_.find(key) != object_.end();
		}

		const Value& operator[](const std::string& key) const
		{
			static const Value null;
			if (type_ != Type::Object)
				return null;
			auto it = object_.find(key);
			return it == object_.end() ? null : it->second;
		}

		// Implicit conversion so a Value can be dropped directly into a
		// std::string field/argument, matching how the call sites use it.
		operator std::string() const { return string_; }

		template <typename T> T get() const;

		// key()/value() pair for range-based iteration over an object,
		// mirroring nlohmann::json's items().
		struct Entry
		{
			const std::string& first;
			const Value& second;
			const std::string& key() const { return first; }
			const Value& value() const { return second; }
		};

		std::vector<Entry> items() const
		{
			std::vector<Entry> out;
			out.reserve(object_.size());
			for (const auto& kv : object_)
				out.push_back(Entry{ kv.first, kv.second });
			return out;
		}

		// Iteration over array elements: for (const auto& e : someArrayValue)
		std::vector<Value>::const_iterator begin() const { return array_.begin(); }
		std::vector<Value>::const_iterator end() const { return array_.end(); }

	private:
		Type type_ = Type::Null;
		std::map<std::string, Value> object_;
		std::vector<Value> array_;
		std::string string_;
		int64_t int_ = 0;
		bool bool_ = false;

		static void skipWs(const std::string& s, size_t& i)
		{
			while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
				++i;
		}

		static std::string parseString(const std::string& s, size_t& i)
		{
			std::string out;
			if (i >= s.size() || s[i] != '"')
				return out;
			++i;
			while (i < s.size() && s[i] != '"')
			{
				char c = s[i];
				if (c == '\\' && i + 1 < s.size())
				{
					char n = s[++i];
					switch (n)
					{
						case 'n': out += '\n'; break;
						case 't': out += '\t'; break;
						case 'r': out += '\r'; break;
						case '"': out += '"'; break;
						case '\\': out += '\\'; break;
						case '/': out += '/'; break;
						case 'b': out += '\b'; break;
						case 'f': out += '\f'; break;
						case 'u':
							// \uXXXX: not needed by the OUI dataset today; skip the
							// 4 hex digits rather than mis-decode them.
							if (i + 4 < s.size())
								i += 4;
							break;
						default: out += n; break;
					}
				}
				else
				{
					out += c;
				}
				++i;
			}
			if (i < s.size())
				++i;  // closing quote
			return out;
		}

		static Value parseObject(const std::string& s, size_t& i)
		{
			Value v;
			v.type_ = Type::Object;
			++i;  // '{'
			skipWs(s, i);
			if (i < s.size() && s[i] == '}')
			{
				++i;
				return v;
			}
			while (i < s.size())
			{
				skipWs(s, i);
				std::string key = parseString(s, i);
				skipWs(s, i);
				if (i < s.size() && s[i] == ':')
					++i;
				skipWs(s, i);
				v.object_.emplace(std::move(key), parseValue(s, i));
				skipWs(s, i);
				if (i < s.size() && s[i] == ',')
				{
					++i;
					continue;
				}
				break;
			}
			skipWs(s, i);
			if (i < s.size() && s[i] == '}')
				++i;
			return v;
		}

		static Value parseArray(const std::string& s, size_t& i)
		{
			Value v;
			v.type_ = Type::Array;
			++i;  // '['
			skipWs(s, i);
			if (i < s.size() && s[i] == ']')
			{
				++i;
				return v;
			}
			while (i < s.size())
			{
				skipWs(s, i);
				v.array_.push_back(parseValue(s, i));
				skipWs(s, i);
				if (i < s.size() && s[i] == ',')
				{
					++i;
					continue;
				}
				break;
			}
			skipWs(s, i);
			if (i < s.size() && s[i] == ']')
				++i;
			return v;
		}

		static Value parseValue(const std::string& s, size_t& i)
		{
			skipWs(s, i);
			if (i >= s.size())
				return Value{};

			char c = s[i];
			if (c == '{')
				return parseObject(s, i);
			if (c == '[')
				return parseArray(s, i);
			if (c == '"')
			{
				Value v;
				v.type_ = Type::String;
				v.string_ = parseString(s, i);
				return v;
			}
			if (c == 't' && s.compare(i, 4, "true") == 0)
			{
				i += 4;
				Value v;
				v.type_ = Type::Boolean;
				v.bool_ = true;
				return v;
			}
			if (c == 'f' && s.compare(i, 5, "false") == 0)
			{
				i += 5;
				Value v;
				v.type_ = Type::Boolean;
				v.bool_ = false;
				return v;
			}
			if (c == 'n' && s.compare(i, 4, "null") == 0)
			{
				i += 4;
				return Value{};
			}

			// number (integers only — sufficient for the OUI dataset's "mask" field)
			size_t start = i;
			if (s[i] == '-' || s[i] == '+')
				++i;
			while (i < s.size() && (std::isdigit(static_cast<unsigned char>(s[i])) || s[i] == '.' || s[i] == 'e' ||
			                         s[i] == 'E' || s[i] == '+' || s[i] == '-'))
				++i;
			Value v;
			v.type_ = Type::Integer;
			try
			{
				v.int_ = std::stoll(s.substr(start, i - start));
			}
			catch (...)
			{
				v.int_ = 0;
			}
			return v;
		}
	};

	template <> inline int Value::get<int>() const { return static_cast<int>(int_); }
	template <> inline int64_t Value::get<int64_t>() const { return int_; }
	template <> inline std::string Value::get<std::string>() const { return string_; }
	template <> inline Value Value::get<Value>() const { return *this; }
}  // namespace vanhooks::net::json
