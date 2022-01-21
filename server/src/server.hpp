#pragma once
#include <cstdint>
#include <public-protocol.hpp>

class Server {
public:
	/**
	 * @brief Construct a new Server instance.
	 *
	 * @param publicPort the port to listen on for public-protocol
	 *                   communications. A value of 0 implies the default port
	 *                   should be used.
	 * @param privatePort the port to listen on for private-protocol
	 *                    communications. A value of 0 implies the default port
	 *                    should be used.
	 */
	Server(std::uint16_t publicPort = 0U, std::uint16_t privatePort = 0U);

	void start();

	const constexpr static std::uint16_t DEFAULT_PUBLIC_PORT = 272U,
	                                     DEFAULT_PRIVATE_PORT = 273U;

protected:
	std::uint16_t publicPort, privatePort;
	PublicProtocol::PublicProtocolManager publicProtoManager;

	/**
	 * @brief Dynamically allocates TCP server parameters for the public port.
	 *
	 * @return Poco::Net::TCPServerParams::Ptr TCP server parameters
	 */
	static Poco::Net::TCPServerParams::Ptr public_tcp_server_params();
	static std::uint16_t default_port(std::uint16_t port,
	                                  std::uint16_t fallbackPort);

	static std::string generate_psk();

	Node get_self();
};
