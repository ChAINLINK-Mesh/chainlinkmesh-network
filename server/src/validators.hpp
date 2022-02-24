#pragma once

#include <Poco/Util/Validator.h>

class PowerOfTwoValidator : public Poco::Util::Validator {
public:
	PowerOfTwoValidator(std::uint64_t min, std::uint64_t max);
	~PowerOfTwoValidator() override = default;

	void validate(const Poco::Util::Option& option,
	              const std::string& value) override;

protected:
	std::uint64_t min, max;
	static constexpr bool is_power_of_two(std::uint64_t value) noexcept;
};

// TODO: Create SocketAddress validator
