#include "Poco/Net/SocketAddress.h"
#include "server.hpp"
#include <iostream>
#include <thread>

const constexpr std::uint16_t DEFAULT_WIREGUARD_PORT = 51820;

int main() {
	// TODO: Replace hard-coded configuration
	Server server{ Server::Configuration{
		  .id = std::nullopt,
		  .controlPlanePublicKey = "",
		  .meshPublicKey = {},
		  .wireGuardAddress =
		      Poco::Net::SocketAddress{ "0.0.0.0", DEFAULT_WIREGUARD_PORT },
		  .publicProtoAddress = std::nullopt,
		  .privateProtoAddress = std::nullopt,
	} };
	server.start();
	while (std::cin.ignore()) {
		std::this_thread::sleep_for(std::chrono::seconds{ 1 });
	}
}
