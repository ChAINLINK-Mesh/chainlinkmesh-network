#include "test.hpp"
#include "app.hpp"
#include <optional>

void test_cli_flags();

void test() {
	test_cli_flags();
}

void test_cli_flags() {
	ServerDaemon daemon{};
	Poco::Util::OptionSet options{};
	daemon.defineOptions(options);

	std::vector<std::pair<std::string, std::optional<std::string>>> flags{
		{ "help", std::nullopt },
		{ "server", std::nullopt },
		{ "control-plane-keylen", "control-plane key length" },
		{ "country", "control-plane certificate country" },
		{ "province", "control-plane certificate province" },
		{ "city", "control-plane certificate city" },
		{ "organisation", "control-plane certificate organisation" },
		{ "common-name", "control-plane certificate common-name" },
		{ "validity-duration", "control-plane certificate validity duration" },
	};

	for (const auto& [flag, name] : flags) {
		if (!options.hasOption(flag)) {
			throw "Server CLI doesn't have a " + name.value_or(flag) + " flag";
		}
	}
}
