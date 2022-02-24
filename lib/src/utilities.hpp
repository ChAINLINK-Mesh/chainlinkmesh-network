#pragma once
#include "types.hpp"
#include <Poco/ByteOrder.h>
#include <Poco/Net/IPAddress.h>
#include <algorithm>
#include <array>
#include <iterator>
#include <numeric>
#include <optional>
#include <span>
#include <string>
#include <type_traits>

/**
 * Compares ranges [begin1..end1) to [begin2..)
 *
 * Assumes that the ranges have equal length.
 *
 * @param begin1 - the start iterator of the first range
 * @param end1 - the iterator past the end of the first range
 * @param begin2 - the start iterator of the second range
 * @return the lexicographical comparison of the two ranges
 */
template <std::input_iterator Iter>
std::strong_ordering compare(Iter begin1, Iter end1, Iter begin2) {
	for (; begin1 != end1; begin1++, begin2++) {
		if (const auto cmp = (*begin1 <=> *begin2); cmp != 0) {
			return cmp;
		}
	}

	return std::strong_ordering::equal;
}

/**
 * Gets the bytestring for an integral type, after converting to little-endian.
 * @tparam Type the integral type being represented
 * @param value the integral value
 * @return the bytestring representing the value
 */
template <std::integral Type>
ByteString get_bytestring(Type value) noexcept {
	const Type littleEndian = Poco::ByteOrder::toLittleEndian(value);
	return ByteString{ reinterpret_cast<const std::uint8_t*>(&littleEndian),
		                 sizeof(littleEndian) };
}

/**
 * Gets the bytestring representing this array of bytes.
 * @tparam count the number of bytes
 * @param value the array of bytes
 * @return an independent copy of the bytes represented by this array
 */
template <size_t count>
ByteString get_bytestring(const std::array<std::uint8_t, count>& value) {
	return ByteString{ value.data(), value.size() };
}

ByteString get_bytestring(Poco::Net::IPAddress address);
ByteString get_bytestring(const std::string& string);
ByteString get_bytestring(const ByteString& string);

template <typename... Types>
ByteString get_bytestring(const Types&... values) requires(sizeof...(Types) >
                                                           1) {
	ByteString bytestring{};

	for (const auto& value :
	     std::vector<ByteString>{ get_bytestring(values)... }) {
		bytestring += value;
	}

	return bytestring;
}

template <std::integral IntType>
constexpr IntType base64_encoded_character_count(IntType bytes) noexcept {
	const constexpr IntType b64GroupAlignment = 3;
	const constexpr IntType b64GroupSize = 4;

	// Round up to nearest B64_ALIGNMENT bytes
	const IntType b64Groups = (bytes + b64GroupAlignment - 1) / b64GroupAlignment;

	return b64GroupSize * b64Groups;
}

std::optional<ByteString> base64_decode(std::string_view bytes);
std::optional<ByteString> base64_decode(std::span<const std::uint8_t> bytes);

std::optional<std::string> base64_encode(ByteString bytes);
std::optional<std::string> base64_encode(std::span<const std::uint8_t> bytes);

std::optional<std::uint64_t>
base64_decoded_character_count(std::uint64_t bytes) noexcept;

bool is_valid_base64_digit(std::uint8_t byte);

std::string trim(const std::string_view& string);
ByteString trim(const ByteStringView& string);
