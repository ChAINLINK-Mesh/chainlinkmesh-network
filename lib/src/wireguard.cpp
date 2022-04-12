#include "wireguard.hpp"
#include "node.hpp"

#include <Poco/ByteOrder.h>
#include <Poco/Net/IPAddress.h>
#include <cstring>

Poco::Net::IPAddress
AbstractWireGuardManager::get_internal_ip_address(std::uint64_t nodeID) {
	const auto beNodeID = Poco::ByteOrder::toBigEndian(nodeID);
	const auto* const idBytes = reinterpret_cast<const std::uint8_t*>(&beNodeID);
	in6_addr addr{};
	std::memcpy(addr.s6_addr, Node::CHAINLINK_NET_PREFIX.data(),
	            Node::CHAINLINK_NET_PREFIX.size());
	std::memcpy(addr.s6_addr + Node::CHAINLINK_NET_PREFIX.size(), idBytes,
	            sizeof(beNodeID));

	// Poco::Net::IPAddress performs memcpy on passed pointer, so no issue using
	// address of local variable.
	return Poco::Net::IPAddress{ &addr, sizeof(addr) };
}

void delete_wireguard_manager(AbstractWireGuardManager* wgManager) {
	delete wgManager;
}

AbstractWireGuardManager*
copy_wireguard_manager(AbstractWireGuardManager* wgManager) {
	return wgManager->clone();
}
