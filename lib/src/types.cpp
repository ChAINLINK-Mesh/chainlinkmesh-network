#include "types.hpp"

#include <Poco/Exception.h>
#include <Poco/Net/DNS.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SocketAddress.h>
#include <exception>
#include <limits>

Host::Host(std::string host, std::uint16_t fallbackPort)
    : dns{ std::move(host) } {
	assert(!dns->empty());

	// If the host contains a colon, either it is a hostname : port, or it is an
	// IP : port pair.
	if (const auto colonPos = dns->find_first_of(':');
	    colonPos != std::string::npos) {
		const auto hostname = dns->substr(0, colonPos);
		const auto portStr = dns->substr(colonPos + 1);

		// Try assigning the port number (after colon). On failure, use fallback.
		try {
			const auto port = std::stoull(portStr);

			if (port > std::numeric_limits<std::uint16_t>::max()) {
				this->portNumber = fallbackPort;
			} else {
				this->portNumber = static_cast<std::uint16_t>(port);
			}
		} catch (std::invalid_argument& /* ignored */) {
			this->portNumber = fallbackPort;
		} catch (std::out_of_range& /* ignored */) {
			this->portNumber = fallbackPort;
		}

		// If IP decoding fails, assume a hostname.
		this->dns = hostname;

		try {
			this->ip = Poco::Net::IPAddress{ hostname };
			this->dns = std::nullopt;
		} catch (Poco::Net::InvalidAddressException& /* ignored */) {
		} catch (Poco::InvalidArgumentException& /* ignored */) {
		}
	} else {
		// Either a hostname or IP without port.
		this->portNumber = fallbackPort;
		try {
			this->ip = Poco::Net::IPAddress{ dns.value() };
			// Fallback to given port if host string doesn't specify.
			this->dns = std::nullopt;
		} catch (Poco::Net::InvalidAddressException& /* ignored */) {
		}
	}
}

Host::Host(Poco::Net::IPAddress host, std::uint16_t port) noexcept
    : ip{ host }, portNumber{ port } {}

Host::Host(const Poco::Net::SocketAddress& host) noexcept
    : ip{ host.host() }, portNumber{ host.port() } {}

Host::operator Poco::Net::IPAddress() const {
	auto& ip = this->ip;

	if (ip.has_value()) {
		return ip.value();
	}

	std::visit(
	    Overload{
	        [&ip](const Poco::Net::IPAddress& resolvedIP) { ip = resolvedIP; },
	        [](const std::exception_ptr& exception) {
		        std::rethrow_exception(exception);
	        },
	    },
	    resolve());

	return ip.value();
}

Host::operator Poco::Net::SocketAddress() const {
	return Poco::Net::SocketAddress{
		static_cast<Poco::Net::IPAddress>(*this),
		portNumber,
	};
}

Expected<Poco::Net::IPAddress> Host::resolve() const noexcept {
	auto& ip = this->ip;

	if (ip.has_value()) {
		return ip.value();
	}

	return std::visit(
	    Overload{
	        [&ip](const Poco::Net::IPAddress& resolvedIP)
	            -> Expected<Poco::Net::IPAddress> {
		        ip = resolvedIP;
		        return resolvedIP;
	        },
	        [](const std::exception_ptr& exception)
	            -> Expected<Poco::Net::IPAddress> { return exception; },
	    },
	    reresolve());
}

Host::operator bool() const noexcept {
	auto& ip = this->ip;

	if (!ip.has_value()) {
		resolve();
	}

	return ip.has_value();
}

Host::operator std::string() const noexcept {
	std::string res{};

	if (dns.has_value()) {
		res = dns.value();
	} else {
		res = ip->toString();
	}

	return res + ":" + std::to_string(portNumber);
}

std::uint16_t Host::port() const noexcept {
	return portNumber;
}

Expected<Poco::Net::IPAddress> Host::reresolve() const noexcept {
	if (!dns.has_value()) {
		return ip.value();
	}

	if (dns->empty()) {
		return std::make_exception_ptr(std::runtime_error{ "Empty hostname" });
	}

	try {
		return Poco::Net::DNS::resolveOne(dns.value());
	} catch (Poco::Net::HostNotFoundException& err) {
		return std::make_exception_ptr(err);
	} catch (Poco::Net::NoAddressFoundException& err) {
		return std::make_exception_ptr(err);
	} catch (Poco::Net::DNSException& err) {
		return std::make_exception_ptr(err);
	} catch (Poco::IOException& err) {
		return std::make_exception_ptr(err);
	} catch (std::exception& err) {
		return std::make_exception_ptr(err);
	}
}
