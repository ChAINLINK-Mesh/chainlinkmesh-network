#pragma once

#include <chrono>
#include <concepts>
#include <memory>

template <typename UnderlyingClock>
requires std::chrono::is_clock_v<UnderlyingClock>
class AbstractClock {
public:
	AbstractClock() = default;
	virtual ~AbstractClock() = default;

	[[nodiscard]] virtual std::chrono::time_point<UnderlyingClock>
	now() const = 0;
};

using BaseUnderlyingClock = std::chrono::system_clock;
using Clock = std::shared_ptr<AbstractClock<BaseUnderlyingClock>>;

class SystemClock : public AbstractClock<BaseUnderlyingClock> {
public:
	SystemClock() = default;
	SystemClock(const SystemClock& other) noexcept = default;
	SystemClock(SystemClock&& other) noexcept = default;
	~SystemClock() override = default;

	[[nodiscard]] std::chrono::time_point<BaseUnderlyingClock>
	now() const override;
};

class TestClock : public AbstractClock<BaseUnderlyingClock> {
public:
	using TimePoint = std::chrono::time_point<BaseUnderlyingClock>;
	using Duration = std::chrono::duration<typename BaseUnderlyingClock::rep,
	                                       typename BaseUnderlyingClock::period>;

	TestClock() = default;
	TestClock(TimePoint initialTimePoint);
	TestClock(Duration initialUTCTimestamp);
	~TestClock() override = default;

	TestClock& operator+=(Duration duration);

	[[nodiscard]] TimePoint now() const override;

protected:
	TimePoint currentTime;
};
