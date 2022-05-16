#include "linux-wireguard-manager.hpp"
#include "error.hpp"
#include "linux-netlink.hpp"
#include "literals.hpp"
#include "utilities.hpp"
#include "wireguard.hpp"

#include <Poco/Net/IPAddress.h>
#include <Poco/Net/SocketAddress.h>
#include <cstring>
#include <iostream>
#include <limits>
#include <memory>
#include <random>
#include <stdexcept>
#include <thread>

extern "C" {
#include <asm/types.h>
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <wireguard.h>
}

static_assert(sizeof(wg_device::public_key) ==
                  AbstractWireGuardManager::WG_KEY_SIZE,
              "WireGuard key size doesn't fit Node details");

LinuxWireGuardManager::LinuxWireGuardManager(
    const Node& self, const std::vector<Node>& nodes,
    const AbstractWireGuardManager::Key& privateKey,
    std::default_random_engine randomEngine)
    : device{ new wg_device{
	        .name = {},
	        .ifindex = 0,
	        .flags = static_cast<enum wg_device_flags>(
	            wg_device_flags::WGDEVICE_HAS_PRIVATE_KEY |
	            wg_device_flags::WGDEVICE_HAS_PUBLIC_KEY |
	            wg_device_flags::WGDEVICE_HAS_LISTEN_PORT),
	        .public_key = {},
	        .private_key = {},
	        .fwmark = 0,
	        .listen_port = self.connectionDetails->wireGuardPort,
	        .first_peer = nullptr,
	        .last_peer = nullptr,
	    } },
      selfID{ self.id }, parentID{ self.parent }, interfaceUp{ false }, ownIP{
	      self.controlPlaneIP
      } {
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
		if (node.id == selfID) {
			continue;
		}

		auto* const peer =
		    LinuxWireGuardManager::wg_peer_from_peer(peer_from_node(node));

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

	// In order to set link device up, we need to interact with the kernel Netlink
	// interface.
	// TODO: Report actual errors.
	if (!NetlinkManager::add_address(device->name, ownIP)) {
		throw std::runtime_error{ "Failed to add IP address to WG interface" };
	}

	if (!NetlinkManager::set_link_up(device->name)) {
		throw std::runtime_error{
			"Failed to activate WG interface (set link status up)"
		};
	}

	interfaceUp = true;
}

void LinuxWireGuardManager::add_peer(const Peer& peer) {
	auto* const wgPeer = LinuxWireGuardManager::wg_peer_from_peer(peer);
	[[maybe_unused]] const auto peerSocket = peer.endpoint.value();
	// teardown_interface();

	if (device->last_peer == nullptr) {
		device->first_peer = wgPeer;
	} else {
		device->last_peer->next_peer = wgPeer;
	}

	device->last_peer = wgPeer;
	// setup_interface();

	// If the interface is not up, don't try and reset its state.
	if (!interfaceUp) {
		return;
	}

	if (const auto ret = wg_set_device(device.get()); ret < 0) {
		throw std::runtime_error{
			"Failed to reconfigure WG interface with error: " + std::to_string(ret)
		};
	}
}

void LinuxWireGuardManager::add_peer(const Node& node) {
	// Ignore requests to add own node.
	if (node.id == selfID) {
		return;
	}

	add_peer(peer_from_node(node));
}

void LinuxWireGuardManager::remove_peer(const Peer& peer) {
	throw std::runtime_error{ "Unimplemented method called" };
}

void LinuxWireGuardManager::remove_peer(const Node& node) {
	remove_peer(peer_from_node(node));
}

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
		.cidr = 128,
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
			.persistent_keepalive_interval = peer.keepalive_interval,
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

LinuxWireGuardManager::Peer
LinuxWireGuardManager::peer_from_node(const Node& node) const {
	std::optional<Poco::Net::SocketAddress> endpoint{};

	if (node.connectionDetails.has_value()) {
		endpoint = Poco::Net::SocketAddress{
			node.connectionDetails->wireGuardHost,
			node.connectionDetails->wireGuardPort,
		};
	}
	return Peer{
		.publicKey = node.wireGuardPublicKey,
		.endpoint = endpoint,
		.internalAddress = node.controlPlaneIP,
		.keepalive_interval = (parentID.has_value() && node.id == parentID.value())
		                          ? KEEPALIVE_INTERVAL
		                          : 0_u16,
	};
}
