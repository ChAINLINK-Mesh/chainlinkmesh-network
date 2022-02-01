#include "server.hpp"

// Assign default controlPlanePort values if custom ports are not specified.
Server::Server(std::uint16_t publicPort, std::uint16_t privatePort)
    : publicPort{ Server::default_port(publicPort, DEFAULT_PUBLIC_PORT) },
      privatePort{ Server::default_port(privatePort, DEFAULT_PRIVATE_PORT) },
      publicProtoManager{ Server::generate_psk(), this->get_self() } {}

void Server::start() {
	this->publicProtoManager.start(Poco::Net::ServerSocket{ this->publicPort },
	                               Server::public_tcp_server_params());
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

std::string Server::generate_psk() {
	// TODO: replace with a cryptographically secure PSK-generation function
	return "Testing Key";
}

Node Server::get_self() {
	// TODO: replace with actual implementation
	return Node{
		.id = 987654321,
		.publicKey = "",
		.meshIP = Poco::Net::IPAddress{ "127.0.0.1" },
	};
}
