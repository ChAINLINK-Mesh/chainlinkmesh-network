#pragma once

#include "types.hpp"

#include <memory>
#include <node.hpp>
#include <random>

extern "C" {
#include <wireguard.h>
}

class LinuxWireGuardManager : public AbstractWireGuardManager {
public:
	LinuxWireGuardManager(const Node& self, const std::vector<Node>& nodes,
	                      const AbstractWireGuardManager::Key& privateKey,
	                      std::default_random_engine randomEngine);
	LinuxWireGuardManager(const LinuxWireGuardManager& other) = default;
	LinuxWireGuardManager(LinuxWireGuardManager&& other) = default;
	~LinuxWireGuardManager() override;

	[[nodiscard]] LinuxWireGuardManager* clone() const override;

	/**
	 * @brief Sets up the WireGuard network interface by communicating with the
	 * kernel.
	 *
	 */
	void setup_interface() override;

	/**
	 * @brief Adds a peer to the WireGuard network interface.
	 *
	 *        Expects this own node not to be added.
	 *
	 * @param peer The peer to add to the WireGuard network.
	 */
	void add_peer(const Peer& peer) override;

	/**
	 * @brief Adds a peer to the WireGuard network interface.
	 *
	 *        Will ignore requests to add this own node.
	 *
	 * @param node The peer to add to the WireGuard network.
	 */
	void add_peer(const Node& node);
	void remove_peer(const Peer& peer) override;
	void remove_peer(const Node& node);

	/**
	 * @brief Deletes the WireGuard network interface by communicating with the
	 * kernel.
	 *
	 */
	void teardown_interface() override;

protected:
	static wg_device* clone_wg_device(wg_device* device);
	static void delete_wg_device(wg_device* device);

	CopyableUniquePtr<wg_device,
	                  FunctionDeleter<LinuxWireGuardManager::delete_wg_device>,
	                  FunctionCopier<LinuxWireGuardManager::clone_wg_device>>
	    device;
	std::uint64_t selfID;
	bool interfaceUp;
	Poco::Net::IPAddress ownIP;

	static wg_peer* wg_peer_from_peer(const Peer& peer);
	static Peer peer_from_node(const Node& node);

	static void setup_interface(wg_device& device);
};
