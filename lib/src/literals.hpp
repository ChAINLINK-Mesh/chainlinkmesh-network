#pragma once

#include <cstdint>
#include <limits>

const unsigned char* operator""_uc(const char* str, unsigned long length);

constexpr std::uint8_t operator""_u8(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::uint8_t>::max();

	if (val > maxVal) {
		throw "value greater than u8 maximum";
	}

	return static_cast<std::uint8_t>(val);
}

constexpr std::uint16_t operator""_u16(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::uint16_t>::max();

	if (val > maxVal) {
		throw "value greater than u16 maximum";
	}

	return static_cast<std::uint16_t>(val);
}

constexpr std::uint32_t operator""_u32(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::uint32_t>::max();

	if (val > maxVal) {
		throw "value greater than u32 maximum";
	}

	return static_cast<std::uint32_t>(val);
}

constexpr std::uint64_t operator""_u64(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::uint64_t>::max();

	if (val > maxVal) {
		throw "value greater than u64 maximum";
	}

	return static_cast<std::uint64_t>(val);
}

constexpr std::int8_t operator""_i8(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::int8_t>::max();

	if (val > maxVal) {
		throw "value greater than i8 maximum";
	}

	return static_cast<std::int8_t>(val);
}

constexpr std::int16_t operator""_i16(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::int16_t>::max();

	if (val > maxVal) {
		throw "value greater than i16 maximum";
	}

	return static_cast<std::int16_t>(val);
}

constexpr std::int32_t operator""_i32(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::int32_t>::max();

	if (val > maxVal) {
		throw "value greater than i32 maximum";
	}

	return static_cast<std::int32_t>(val);
}

constexpr std::int64_t operator""_i64(unsigned long long val) {
	const constexpr auto maxVal = std::numeric_limits<std::int64_t>::max();

	if (val > maxVal) {
		throw "value greater than i64 maximum";
	}

	return static_cast<std::int64_t>(val);
}
