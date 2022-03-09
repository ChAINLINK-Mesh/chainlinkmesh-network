#include "linux-wireguard-manager.hpp"
#include "utilities.hpp"
#include "wireguard.h"
#include "wireguard.hpp"
#include <Poco/Net/IPAddress.h>
#include <Poco/Net/SocketAddress.h>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>

extern "C" {
#include <asm/types.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
}

static_assert(sizeof(wg_device::public_key) ==
                  AbstractWireGuardManager::WG_PUBKEY_SIZE,
              "WireGuard key size doesn't fit Node details");

LinuxWireGuardManager::LinuxWireGuardManager(
    const Node& self, const std::vector<Node>& nodes,
    const AbstractWireGuardManager::Key& privateKey,
    std::default_random_engine randomEngine)
    : device{ new wg_device{
	        .name = "",
	        .ifindex = 0,
	        .flags = static_cast<enum wg_device_flags>(
	            wg_device_flags::WGDEVICE_HAS_PRIVATE_KEY |
	            wg_device_flags::WGDEVICE_HAS_PUBLIC_KEY |
	            wg_device_flags::WGDEVICE_HAS_LISTEN_PORT),
	        .public_key = {},
	        .private_key = {},
	        .fwmark = 0,
	        .listen_port = self.wireGuardPort,
	        .first_peer = nullptr,
	        .last_peer = nullptr,
	    } },
      interfaceUp{ false }, ownIP{ self.controlPlaneIP } {
	// TODO: Double-check this name generation.
	std::uniform_int_distribution<std::uint16_t> interfaceDistribution{
		std::numeric_limits<std::uint16_t>::min(),
		std::numeric_limits<std::uint16_t>::max()
	};
	std::snprintf(device->name, sizeof(device->name), "chainlink-%d",
	              interfaceDistribution(randomEngine));
	std::memcpy(device->public_key, self.wireGuardPublicKey.data(),
	            sizeof(device->public_key));
	std::memcpy(device->private_key, privateKey.data(),
	            sizeof(device->public_key));

	wg_peer** prevPeer = nullptr;

	for (const auto& node : nodes) {
		auto* const peer = LinuxWireGuardManager::wg_peer_from_peer(Peer{
		    .publicKey = node.wireGuardPublicKey,
		    .endpoint =
		        Poco::Net::SocketAddress{ node.wireGuardIP, node.wireGuardPort },
		    .internalAddress = node.controlPlaneIP,
		});

		if (prevPeer == nullptr) {
			device->first_peer = peer;
		} else {
			*prevPeer = peer;
		}

		// Avoid erasing last peer pointer
		if (peer->next_peer != nullptr) {
			prevPeer = &peer->next_peer;
		}
	}

	if (prevPeer != nullptr) {
		device->last_peer = *prevPeer;
	}
}

LinuxWireGuardManager::~LinuxWireGuardManager() {
	if (device) {
		try {
			teardown_interface();
		} catch (const std::runtime_error& e) {
			std::cerr << "Error tearing down WireGuard interface: " << e.what()
			          << "\n";
		}

		device.reset();
	}
}

LinuxWireGuardManager* LinuxWireGuardManager::clone() const {
	return new LinuxWireGuardManager{ *this };
}

void LinuxWireGuardManager::setup_interface() {
	// Unclear what the semantics of repeated setup_interface() calls should be.
	assert(!interfaceUp);

	// Only supports IPv6 addresses.
	assert(ownIP.family() == Poco::Net::AddressFamily::IPv6);

	if (const auto ret = wg_add_device(device->name); ret < 0) {
		throw std::runtime_error{ "Failed to setup WG interface with error: " +
			                        std::to_string(ret) };
	}

	if (const auto ret = wg_set_device(device.get()); ret < 0) {
		throw std::runtime_error{ "Failed to setup WG interface with error: " +
			                        std::to_string(ret) };
	}

	// In order to set link device up, we need to first create a socket. Any
	// socket will do.
	const auto sockDeleter = [](const int* const s) { close(*s); };
	auto tmpSocket = std::unique_ptr<int, FunctionDeleter<sockDeleter>>{ new int{
		  socket(AF_INET, SOCK_DGRAM, 0) } };

	if (*tmpSocket < 0) {
		throw std::runtime_error{
			"Failed to create temporary socket for configuring WG interface: " +
			std::to_string(-*tmpSocket)
		};
	}

	ifreq ifr{};
	strncpy(ifr.ifr_name, device->name, IFNAMSIZ);

	// Now get the interface index, as this is required for setting IPv6
	// properties.
	if (const auto res = ioctl(*tmpSocket, SIOCGIFINDEX, &ifr); res < 0) {
		throw std::runtime_error{ "Failed to get index of WG interface: " +
			                        std::to_string(-res) };
	}

	struct in6_ifreq ifr6 {
		.ifr6_addr = *reinterpret_cast<const in6_addr*>(ownIP.addr()),
		.ifr6_prefixlen = ownIP.prefixLength(), .ifr6_ifindex = ifr.ifr_ifindex,
	};

	// TODO: May be unhappy that socket is IPv6
	tmpSocket = std::unique_ptr<int, FunctionDeleter<sockDeleter>>{ new int{
		  socket(AF_INET6, SOCK_DGRAM, 0) } };

	if (const auto res = ioctl(*tmpSocket, SIOCSIFADDR, &ifr6); res < 0) {
		throw std::runtime_error{ "Failed to set IP address on WG interface: " +
			                        std::to_string(-res) };
	}

	// Revert back to IPv4 to allow setting the interface device to 'up' status.
	tmpSocket = std::unique_ptr<int, FunctionDeleter<sockDeleter>>{ new int{
		  socket(AF_INET, SOCK_DGRAM, 0) } };

	if (*tmpSocket < 0) {
		throw std::runtime_error{
			"Failed to create temporary socket for configuring WG interface: " +
			std::to_string(-*tmpSocket)
		};
	}

	if (const auto res = ioctl(*tmpSocket, SIOCGIFFLAGS, &ifr); res < 0) {
		throw std::runtime_error{ "Failed to get WG interface link flags: " +
			                        std::to_string(-res) };
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

	if (const auto res = ioctl(*tmpSocket, SIOCSIFFLAGS, &ifr); res < 0) {
		throw std::runtime_error{ "Failed to set WG interface up: " +
			                        std::to_string(-res) };
	};

	// const auto tmpSocket = std::unique_ptr<int, FunctionDeleter<close>>{ new
	// int{ 	  socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) } }; if (*tmpSocket <
	// 0) {
	//	throw std::runtime_error{
	//		"Failed to create temporary socket for configuring WG interface"
	//	};
	//}

	// rtattr attr;

	interfaceUp = true;
}

void LinuxWireGuardManager::add_peer(const Peer& peer) {
	auto* const wgPeer = LinuxWireGuardManager::wg_peer_from_peer(peer);
	// teardown_interface();

	if (device->last_peer == nullptr) {
		device->first_peer = wgPeer;
	} else {
		device->last_peer->next_peer = wgPeer;
	}

	device->last_peer = wgPeer;
	// setup_interface();

	if (const auto ret = wg_set_device(device.get()); ret < 0) {
		throw std::runtime_error{
			"Failed to reconfigure WG interface with error: " + std::to_string(ret)
		};
	}
}

void LinuxWireGuardManager::remove_peer(const Peer& peer) {}

void LinuxWireGuardManager::teardown_interface() {
	// If the interface is not up, opportunistically return.
	if (!interfaceUp) {
		return;
	}

	if (const auto ret = wg_del_device(device->name); ret < 0) {
		throw std::runtime_error{ "Failed to setup WG interface with error: " +
			                        std::to_string(ret) };
	}

	interfaceUp = false;
}

wg_device* LinuxWireGuardManager::clone_wg_device(wg_device* device) {
	auto* clonedDevice = new wg_device{
		.name = {},
		.ifindex = device->ifindex,
		.flags = device->flags,
		.public_key = {},
		.private_key = {},
		.fwmark = device->fwmark,
		.listen_port = device->listen_port,
		.first_peer = nullptr,
		.last_peer = nullptr,
	};
	std::memcpy(clonedDevice->name, device->name, sizeof(clonedDevice->name));
	std::memcpy(clonedDevice->public_key, device->public_key,
	            sizeof(clonedDevice->public_key));
	std::memcpy(clonedDevice->private_key, device->private_key,
	            sizeof(clonedDevice->private_key));

	wg_peer* peer = nullptr;
	wg_peer** clonedPeer = nullptr;

	wg_for_each_peer(device, peer) {
		auto* const newPeer = new wg_peer{
			.flags = peer->flags,
			.public_key = {},
			.preshared_key = {},
			.endpoint = {},
			.last_handshake_time = peer->last_handshake_time,
			.rx_bytes = peer->rx_bytes,
			.tx_bytes = peer->tx_bytes,
			.persistent_keepalive_interval = peer->persistent_keepalive_interval,
			.first_allowedip = nullptr,
			.last_allowedip = nullptr,
			.next_peer = nullptr,
		};

		std::memcpy(newPeer->public_key, peer->public_key,
		            sizeof(newPeer->public_key));
		std::memcpy(newPeer->preshared_key, peer->preshared_key,
		            sizeof(newPeer->preshared_key));

		switch (peer->endpoint.addr.sa_family) {
			case AF_INET:
				std::memcpy(&newPeer->endpoint.addr4, &peer->endpoint.addr4,
				            sizeof(newPeer->endpoint.addr4));
				break;
			case AF_INET6:
				std::memcpy(&newPeer->endpoint.addr6, &peer->endpoint.addr6,
				            sizeof(newPeer->endpoint.addr6));
				break;
			default:
				throw std::invalid_argument{ "Unexpected endpoint address family" };
		}

		if (clonedPeer == nullptr) {
			clonedDevice->first_peer = newPeer;
		} else {
			// Update previous peer's next_peer pointer
			*clonedPeer = newPeer;
		}

		wg_allowedip* allowedIP = nullptr;
		wg_allowedip** clonedAllowedIP = nullptr;

		wg_for_each_allowedip(peer, allowedIP) {
			auto* const newAllowedIP = new wg_allowedip{
				.family = allowedIP->family,
				.ip6 = {},
				.cidr = allowedIP->cidr,
				.next_allowedip = nullptr,
			};

			switch (allowedIP->family) {
				case AF_INET:
					std::memcpy(&newAllowedIP->ip4, &allowedIP->ip4,
					            sizeof(newAllowedIP->ip4));
					break;
				case AF_INET6:
					std::memcpy(&newAllowedIP->ip6, &newAllowedIP->ip6,
					            sizeof(newAllowedIP->ip6));
					break;
				default:
					throw std::invalid_argument{ "Unexpected allowed IP address family" };
			}

			if (clonedAllowedIP == nullptr) {
				newPeer->first_allowedip = newAllowedIP;
			} else {
				*clonedAllowedIP = newAllowedIP;
			}

			// Avoid erasing the pointer to the last allowedip
			if (allowedIP->next_allowedip != nullptr) {
				clonedAllowedIP = &newAllowedIP->next_allowedip;
			}
		}

		if (clonedAllowedIP != nullptr) {
			newPeer->last_allowedip = *clonedAllowedIP;
		}

		// Avoid erasing the pointer to the last peer
		if (peer->next_peer != nullptr) {
			clonedPeer = &newPeer->next_peer;
		}
	}

	if (clonedPeer != nullptr) {
		clonedDevice->last_peer = *clonedPeer;
	}

	return clonedDevice;
}

void LinuxWireGuardManager::delete_wg_device(wg_device* device) {
	for (wg_peer* peer = device->first_peer; peer != nullptr;) {
		// Zero out pointers to flush out memory access bugs
		for (wg_allowedip* allowedIP = peer->first_allowedip;
		     allowedIP != nullptr;) {
			wg_allowedip* next = allowedIP->next_allowedip;
			allowedIP->next_allowedip = nullptr;
			delete allowedIP;
			allowedIP = next;
		}

		peer->first_allowedip = nullptr;
		peer->last_allowedip = nullptr;

		wg_peer* next = peer->next_peer;
		peer->next_peer = nullptr;
		delete peer;
		peer = next;
	}

	device->first_peer = nullptr;
	device->last_peer = nullptr;
	delete device;
}

wg_peer* LinuxWireGuardManager::wg_peer_from_peer(const Peer& peer) {
	auto* const ip = new wg_allowedip{
		.family = static_cast<std::uint16_t>(peer.internalAddress.af()),
		.ip6 = {},
		.cidr = static_cast<std::uint8_t>(peer.internalAddress.prefixLength()),
		.next_allowedip = nullptr,
	};

	std::memcpy(&ip->ip6, peer.internalAddress.addr(), sizeof(in6_addr));

	auto* const wgPeer = new wg_peer{
			.flags = static_cast<wg_peer_flags>(wg_peer_flags::WGPEER_HAS_PUBLIC_KEY | wg_peer_flags::WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL),
			.public_key = {},
			.preshared_key = {},
			.endpoint = {},
			.last_handshake_time = {
				.tv_sec = 0,
				.tv_nsec = 0,
			},
			.rx_bytes = 0,
			.tx_bytes = 0,
			.persistent_keepalive_interval = 25,
			.first_allowedip = ip,
			.last_allowedip = ip,
			.next_peer = nullptr,
		};

	std::memcpy(wgPeer->public_key, peer.publicKey.data(), peer.publicKey.size());

	if (peer.endpoint) {
		const auto endpoint = peer.endpoint.value();

		switch (endpoint.family()) {
			case Poco::Net::IPAddress::Family::IPv4:
				assert(endpoint.length() == sizeof(sockaddr_in));
				std::memcpy(&wgPeer->endpoint.addr4, endpoint.addr(),
				            endpoint.length());
				break;
			case Poco::Net::IPAddress::Family::IPv6:
				assert(endpoint.length() == sizeof(sockaddr_in6));
				std::memcpy(&wgPeer->endpoint.addr6, endpoint.addr(),
				            endpoint.length());
				break;
			case Poco::Net::IPAddress::Family::UNIX_LOCAL:
				throw std::invalid_argument{ "Cannot specify Unix peer addresses" };
		}
	}

	return wgPeer;
}