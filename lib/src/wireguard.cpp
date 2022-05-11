#include "wireguard.hpp"
#include "node.hpp"

#include <Poco/ByteOrder.h>
#include <Poco/Net/IPAddress.h>
#include <cstring>

void delete_wireguard_manager(AbstractWireGuardManager* wgManager) {
	delete wgManager;
}

AbstractWireGuardManager*
copy_wireguard_manager(AbstractWireGuardManager* wgManager) {
	return wgManager->clone();
}
