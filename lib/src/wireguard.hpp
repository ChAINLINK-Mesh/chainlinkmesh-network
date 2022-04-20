#pragma once

#include "types.hpp"

#include <Poco/Net/IPAddress.h>
#include <Poco/Net/SocketAddress.h>
#include <optional>

/**
 * @brief The abstract class representing WireGuard manager implementations.
 *
 * Facade interface to platform-specific APIs.
 */
class AbstractWireGuardManager {
public:
	AbstractWireGuardManager() = default;
	virtual ~AbstractWireGuardManager() = default;

	/**
	 * @brief Constructs a new object with `new()`, which copies all of the values
	 * from this object.
	 *
	 * Returns a dynamic copy of of the current object.
	 */
	[[nodiscard]] virtual AbstractWireGuardManager* clone() const = 0;

	static const constexpr std::uint32_t WG_KEY_SIZE = 32;
	using Key = std::array<std::uint8_t, WG_KEY_SIZE>;

	struct Peer {
		Key publicKey;
		std::optional<Poco::Net::SocketAddress> endpoint;
		Poco::Net::IPAddress internalAddress;
	};

	/**
	 * @brief Creates the WireGuard interface, connected to the current peers.
	 *
	 */
	virtual void setup_interface() = 0;

	/**
	 * @brief Adds a peer to the WireGuard network. May require tearing down the
	 * interface momentarily.
	 *
	 * @param peer The peer to add to the network.
	 */
	virtual void add_peer(const Peer& peer) = 0;

	/**
	 * @brief Removes a peer from the WireGuard network. May require tearing down
	 * the interface momentarily.
	 *
	 * @param peer The peer to remove from the network.
	 */
	virtual void remove_peer(const Peer& peer) = 0;

	/**
	 * @brief Shutdown and delete the WireGuard interface.
	 *
	 */
	virtual void teardown_interface() = 0;

	Poco::Net::IPAddress static get_internal_ip_address(std::uint64_t nodeID);
};

void delete_wireguard_manager(AbstractWireGuardManager* wgManager);

AbstractWireGuardManager*
copy_wireguard_manager(AbstractWireGuardManager* wgManager);

using WireGuardManager =
    CopyableUniquePtr<AbstractWireGuardManager,
                      FunctionDeleter<delete_wireguard_manager>,
                      FunctionCopier<copy_wireguard_manager>>;
