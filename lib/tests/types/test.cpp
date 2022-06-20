#include "error.hpp"
#include "types.hpp"

void test_host_construction();
void test_host_resolution();
void test_host_formatting();

void test() {
	test_host_construction();
	test_host_resolution();
	test_host_formatting();
}

void test_host_construction() {
	{
		const std::string demoHost = "127.0.0.1";
		const std::uint16_t demoPort = 234;
		Host host{ demoHost, demoPort };

		if (const auto resolved = host.resolve();
		    !successful(resolved) ||
		    get_expected(resolved) != Poco::Net::IPAddress{ demoHost }) {
			throw "Failed to construct host from IP address string";
		}

		if (const auto port = host.port(); port != demoPort) {
			throw "Failed to construct port from fallback port";
		}
	}

	{
		const std::string demoHost = "127.0.0.1";
		const std::uint16_t demoPort = 234;
		const std::uint16_t demoPortFallback = 567;
		Host host{ demoHost + ":" + std::to_string(demoPort), demoPortFallback };

		if (const auto resolved = host.resolve();
		    !successful(resolved) ||
		    get_expected(resolved) != Poco::Net::IPAddress{ demoHost }) {
			throw "Failed to construct host from socket address string";
		}

		if (const auto port = host.port(); port != demoPort) {
			throw "Failed to construct port from socket address string";
		}
	}

	{
		const std::string demoHost = "127.0.0.1";
		const std::uint16_t demoPort = 234;
		Host host{ Poco::Net::IPAddress{ demoHost }, demoPort };

		if (const auto resolved = host.resolve();
		    !successful(resolved) ||
		    get_expected(resolved) != Poco::Net::IPAddress{ demoHost }) {
			throw "Failed to construct host from IP address";
		}

		if (const auto port = host.port(); port != demoPort) {
			throw "Failed to construct port from IP address";
		}
	}

	{
		const std::string demoHost = "127.0.0.1";
		const std::uint16_t demoPort = 234;
		Host host{ Poco::Net::SocketAddress{ demoHost, demoPort } };

		if (const auto resolved = host.resolve();
		    !successful(resolved) ||
		    get_expected(resolved) != Poco::Net::IPAddress{ demoHost }) {
			throw "Failed to construct host from socket address";
		}
	}

	{
		const std::string demoHost = "localhost";
		const std::uint16_t demoPort = 234;
		Host host{ demoHost, demoPort };

		if (const auto port = host.port(); port != demoPort) {
			throw "Failed to construct port from hostname's fallback port";
		}
	}

	{
		const std::string demoHost = "localhost";
		const std::uint16_t demoPort = 234;
		const std::uint16_t demoFallbackPort = 456;
		Host host{ demoHost + ":" + std::to_string(demoPort), demoFallbackPort };

		if (const auto port = host.port(); port != demoPort) {
			throw "Failed to construct port from hostname-with-port's fallback port";
		}
	}
}

void test_host_resolution() {
	const std::string demoHost = "localhost";
	const Poco::Net::IPAddress demoHostAddress4 =
	    Poco::Net::IPAddress{ "127.0.0.1" };
	const Poco::Net::IPAddress demoHostAddress6 = Poco::Net::IPAddress{ "::1" };
	const std::uint16_t demoPort = 234;
	Host host{ demoHost, demoPort };

	const auto resolved = host.resolve();

	if (!successful(resolved)) {
		throw "Failed to resolve hostname";
	}

	const auto ip = get_expected(resolved);

	if (ip.family() == Poco::Net::IPAddress::IPv4) {
		if (ip != demoHostAddress4) {
			throw "Resolved hostname to wrong address";
		}
	} else {
		assert(ip.family() == Poco::Net::IPAddress::IPv6);

		if (ip != demoHostAddress6) {
			throw "Resolved hostname to wrong address";
		}
	}
}

void test_host_formatting() {
	const std::string demoHost = "localhost";
	const std::uint16_t demoPort = 234;
	Host host{ demoHost, demoPort };

	if (static_cast<std::string>(host) !=
	    demoHost + ":" + std::to_string(demoPort)) {
		throw "Failed to format host correctly";
	}
}
