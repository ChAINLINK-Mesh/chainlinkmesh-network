#include "types.hpp"

#include <Poco/Exception.h>
#include <Poco/Net/DNS.h>
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/NetException.h>
#include <Poco/Net/SocketAddress.h>
#include <exception>

Host::Host(std::string host) : dns{ host } {
	assert(!host.empty());

	// If the host represents an IP instead, mark it as such.
	try {
		const Poco::Net::SocketAddress socketAddr{ host };
		this->ip = socketAddr.host();
		this->portNumber = socketAddr.port();
		this->dns = std::nullopt;
	} catch (Poco::Net::InvalidAddressException& /* ignored */) {
	} catch (Poco::InvalidArgumentException& /* ignored */) {
	}

	if (!this->ip) {
		try {
			this->ip = Poco::Net::IPAddress{ host };
			this->dns = std::nullopt;
		} catch (Poco::Net::InvalidAddressException& err) {
		}
	}
}

Host::Host(Poco::Net::IPAddress host) noexcept : ip{ host } {}

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
	return dns.value_or(ip->toString());
}

std::optional<std::uint16_t> Host::port() const noexcept {
	// TODO: Do SRV / TXT DNS lookup to find associated port.
	return portNumber;
}

Expected<Poco::Net::IPAddress> Host::reresolve() const noexcept {
	if (!dns.has_value()) {
		return ip.value();
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
