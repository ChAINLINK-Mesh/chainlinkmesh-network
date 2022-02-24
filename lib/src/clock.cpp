#include "clock.hpp"

std::chrono::time_point<BaseUnderlyingClock> SystemClock::now() const {
	return BaseUnderlyingClock::now();
}

TestClock::TestClock(TimePoint initialTimePoint)
    : currentTime{ initialTimePoint } {}

TestClock::TestClock(Duration initialUTCTimestamp)
    : currentTime{ initialUTCTimestamp } {}

TestClock& TestClock::operator+=(Duration duration) {
	this->currentTime += duration;
	return *this;
}

TestClock::TimePoint TestClock::now() const {
	return this->currentTime;
}
