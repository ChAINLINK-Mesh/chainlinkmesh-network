#include "test.hpp"
#include "validators.hpp"
#include <Poco/Util/Option.h>
#include <Poco/Util/OptionException.h>
#include <stdexcept>

void test_power_of_two();

void test() {
	test_power_of_two();
}

void test_power_of_two() {
	try {
		[[maybe_unused]] PowerOfTwoValidator invalidValidator{ 0, 0 };
		throw "Created invalid Power-of-Two validator";
	} catch (const std::invalid_argument& /* ignored */) {
	}

	try {
		[[maybe_unused]] PowerOfTwoValidator invalidValidator{ 3, 4 };
		throw "Created invalid Power-of-Two validator";
	} catch (const std::invalid_argument& /* ignored */) {
	}

	const auto option =
	    Poco::Util::Option{ "test-option", "", "option for testing validators" }
	        .validator(new PowerOfTwoValidator{ 2, 8 });

	const std::vector<std::tuple<std::string, bool, std::string>> testCases{
		{ "", false, "Validated empty string as a power of two" },
		{ "t", false, "Validated word as a power of two" },
		{ "1", false, "Validated power of two below minimum of permitted range" },
		{ "2", true, "Failed to validate minimum power of two" },
		{ "4", true, "Failed to validate power of two within range" },
		{ "8", true, "Failed to validate maximum power of two" },
		{ "16", false, "Validated power of two above maximum of permitted range" },
	};

	for (const auto& [testCase, shouldSucceed, errorMessage] : testCases) {
		try {
			option.validator()->validate(option, testCase);

			if (!shouldSucceed) {
				throw errorMessage;
			}
		} catch (const Poco::Util::OptionException& e) {
			if (shouldSucceed) {
				throw errorMessage + ": " + e.message();
			}
		}
	}
}
