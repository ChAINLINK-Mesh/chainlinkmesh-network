#include "server.hpp"

// Assign default port values if custom ports are not specified.
Server::Server(std::uint16_t publicPort, std::uint16_t privatePort)
    : publicPort{ Server::default_port(publicPort, DEFAULT_PUBLIC_PORT) },
      privatePort{ Server::default_port(privatePort, DEFAULT_PRIVATE_PORT) },
      publicProtoManager{ Poco::Net::ServerSocket{ this->publicPort },
	                        Server::public_tcp_server_params() } {}

void Server::start() {
	this->publicProtoManager.start();
}

Poco::Net::TCPServerParams::Ptr Server::public_tcp_server_params() {
	auto* params = new Poco::Net::TCPServerParams{};
	params->setMaxThreads(1);
	params->setMaxQueued(4);

	return params;
}

std::uint16_t Server::default_port(std::uint16_t port,
                                   std::uint16_t fallbackPort) {
	return port == 0 ? fallbackPort : port;
}
