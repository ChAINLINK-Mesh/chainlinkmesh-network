#pragma once

#include "types.hpp"
#include <memory>
#include <node.hpp>
#include <random>
#include <wireguard.hpp>

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

	void setup_interface() override;
	void add_peer(const Peer& peer) override;
	void remove_peer(const Peer& peer) override;
	void teardown_interface() override;

protected:
	static wg_device* clone_wg_device(wg_device* device);
	static void delete_wg_device(wg_device* device);

	CopyableUniquePtr<wg_device,
	                  FunctionDeleter<LinuxWireGuardManager::delete_wg_device>,
	                  FunctionCopier<LinuxWireGuardManager::clone_wg_device>>
	    device;
	bool interfaceUp;
	Poco::Net::IPAddress ownIP;

	static wg_peer* wg_peer_from_peer(const Peer& peer);

	static void setup_interface(wg_device& device);
};
