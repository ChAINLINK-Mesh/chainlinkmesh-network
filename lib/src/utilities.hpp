#pragma once
#include <algorithm>
#include <array>
#include <string>
#include <iterator>
#include <Poco/ByteOrder.h>
#include <Poco/Net/IPAddress.h>
#include <numeric>
#include <optional>
#include <span>

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

using ByteString = std::basic_string<std::uint8_t>;

/**
 * Gets the bytestring for an integral type, after converting to little-endian.
 * @tparam Type the integral type being represented
 * @param value the integral value
 * @return the bytestring representing the value
 */
template<std::integral Type>
ByteString get_bytestring(const Type value) noexcept {
	const Type littleEndian = Poco::ByteOrder::toLittleEndian(value);
	return ByteString{ reinterpret_cast<const std::uint8_t*>(&littleEndian), sizeof(littleEndian) };
}

/**
 * Gets the bytestring representing this array of bytes.
 * @tparam count the number of bytes
 * @param value the array of bytes
 * @return an independent copy of the bytes represented by this array
 */
template <size_t count>
ByteString get_bytestring(const std::array<std::uint8_t, count> value) {
	return ByteString{ value.data(), value.size() };
}

ByteString get_bytestring(Poco::Net::IPAddress address);

template <typename... Types>
ByteString get_bytestring(const Types... values) {
	ByteString bytestring{};

	for (const auto value : (get_bytestring(values), ...)) {
		bytestring += value;
	}

	return bytestring;
}

template <std::integral IntType>
constexpr IntType base64_encoded_character_count(IntType bytes) noexcept {
	const constexpr IntType b64GroupAlignment = 3;
	const constexpr IntType b64GroupSize = 4;

	// Round up to nearest B64_ALIGNMENT bytes
	const IntType b64Groups =
			(bytes + b64GroupAlignment - 1) / b64GroupAlignment;

	return b64GroupSize * b64Groups;
}

std::optional<ByteString> base64_decode(std::string_view bytes);
std::optional<ByteString> base64_decode(std::span<const std::uint8_t> bytes);

template <std::integral IntType>
constexpr IntType base64_decoded_character_count(IntType bytes) noexcept;

std::string trim(const std::string& string);
