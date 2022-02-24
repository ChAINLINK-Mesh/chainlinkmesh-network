#include "validators.hpp"
#include "Poco/Util/OptionException.h"

#include <cassert>
#include <cstdlib>
#include <limits>
#include <stdexcept>

PowerOfTwoValidator::PowerOfTwoValidator(std::uint64_t min, std::uint64_t max)
    : min{ min }, max{ max } {
	if (!PowerOfTwoValidator::is_power_of_two(min) ||
	    !PowerOfTwoValidator::is_power_of_two(max)) {
		throw std::invalid_argument{ "min and max should be powers of two" };
	}
}

void PowerOfTwoValidator::validate(const Poco::Util::Option& /* unused */,
                                   const std::string& value) {
	assert(value.size() < std::numeric_limits<int>::max());
	char* end = nullptr;
	const constexpr auto base = 10;
	std::int64_t intVal = std::strtoll(value.c_str(), &end, base);

	if (end == value.c_str() || *end != '\0') {
		throw Poco::Util::OptionException{ "value '" + value +
			                                 "' is not an integer" };
	}

	if (!PowerOfTwoValidator::is_power_of_two(intVal)) {
		throw Poco::Util::OptionException{ "value " + value +
			                                 " is not a power of two" };
	}

	if (intVal < min || intVal > max) {
		throw Poco::Util::OptionException{ "value is outside of accepted range [" +
			                                 std::to_string(min) + ", " +
			                                 std::to_string(max) + "]" };
	}
}

constexpr bool
PowerOfTwoValidator::is_power_of_two(std::uint64_t value) noexcept {
	return value != 0 && ((value & (value - 1)) == 0);
}
