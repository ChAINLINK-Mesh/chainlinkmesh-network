#include "linux-netlink.hpp"

#include "types.hpp"

extern "C" {
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <netlink/addr.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <sys/socket.h>
};

using NL_SOCK_RAII = std::unique_ptr<nl_sock, FunctionDeleter<nl_socket_free>>;
using NL_CACHE_RAII = std::unique_ptr<nl_cache, FunctionDeleter<nl_cache_free>>;
using RTNL_LINK_RAII =
    std::unique_ptr<rtnl_link, FunctionDeleter<rtnl_link_put>>;
using NL_ADDR_RAII = std::unique_ptr<nl_addr, FunctionDeleter<nl_addr_put>>;
using RTNL_ADDR_RAII =
    std::unique_ptr<rtnl_addr, FunctionDeleter<rtnl_addr_put>>;

const constexpr std::uint8_t IPV6_PREFIX_LENGTH = 64;
const constexpr std::uint8_t IPV4_PREFIX_LENGTH = 32;

bool NetlinkManager::add_address(const std::string& interfaceName,
                                 const Poco::Net::IPAddress& address) {
	// Only handle IP addresses
	assert(address.af() == AF_INET || address.af() == AF_INET6);

	NL_SOCK_RAII nlSocket{ nl_socket_alloc() };

	if (nlSocket == nullptr) {
		return false;
	}

	// Connection closed automatically by nl_socket_free when it goes out of
	// scope.
	if (nl_connect(nlSocket.get(), NETLINK_ROUTE) < 0) {
		return false;
	}

	nl_cache* tempNLCache{};
	if (rtnl_link_alloc_cache(nlSocket.get(), address.af(), &tempNLCache) < 0) {
		return false;
	}

	NL_CACHE_RAII nlCache{ tempNLCache };
	RTNL_LINK_RAII rtnlLink{ rtnl_link_get_by_name(nlCache.get(),
		                                             interfaceName.c_str()) };

	if (rtnlLink == nullptr) {
		return false;
	}

	RTNL_ADDR_RAII rtnlAddr{ rtnl_addr_alloc() };

	if (rtnlAddr == nullptr) {
		return false;
	}

	rtnl_addr_set_ifindex(rtnlAddr.get(), rtnl_link_get_ifindex(rtnlLink.get()));

	NL_ADDR_RAII nlAddr{ nl_addr_build(address.af(), address.addr(),
		                                 address.length()) };

	if (nlAddr == nullptr) {
		return false;
	}

	switch (address.af()) {
		case AF_INET:
			nl_addr_set_prefixlen(nlAddr.get(), IPV4_PREFIX_LENGTH);
			break;
		case AF_INET6:
			nl_addr_set_prefixlen(nlAddr.get(), IPV6_PREFIX_LENGTH);
			break;
	}

	if (rtnl_addr_set_local(rtnlAddr.get(), nlAddr.get()) < 0) {
		return false;
	}

	return rtnl_addr_add(nlSocket.get(), rtnlAddr.get(), 0) >= 0;
}

bool NetlinkManager::set_link_up(const std::string& interfaceName) {
	NL_SOCK_RAII nlSocket{ nl_socket_alloc() };

	if (nlSocket == nullptr) {
		return false;
	}

	// Connection closed automatically by nl_socket_free when it goes out of
	// scope.
	if (nl_connect(nlSocket.get(), NETLINK_ROUTE) < 0) {
		return false;
	}

	nl_cache* tempNLCache{};
	if (rtnl_link_alloc_cache(nlSocket.get(), AF_UNSPEC, &tempNLCache) < 0) {
		return false;
	}

	NL_CACHE_RAII nlCache{ tempNLCache };
	RTNL_LINK_RAII rtnlLink{ rtnl_link_get_by_name(nlCache.get(),
		                                             interfaceName.c_str()) };

	if (rtnlLink == nullptr) {
		return false;
	}

	RTNL_LINK_RAII rtnlLinkChange{ rtnl_link_alloc() };

	if (rtnlLinkChange == nullptr) {
		return false;
	}

	rtnl_link_set_flags(rtnlLinkChange.get(), IFF_UP);

	return rtnl_link_change(nlSocket.get(), rtnlLink.get(), rtnlLinkChange.get(),
	                        0) >= 0;
}
