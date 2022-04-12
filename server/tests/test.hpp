#pragma once

#include "server.hpp"

#include <Poco/Net/SocketAddress.h>

struct TestPorts {
	Poco::Net::SocketAddress wireGuardAddress;
	Poco::Net::SocketAddress publicProtoAddress;
	Poco::Net::SocketAddress privateProtoAddress;
};

ByteString read_file(const std::string& filename);
Server get_server(Server::Configuration config);

/**
 * @brief Gets a randomised configuration of ports to use for testing. Repeated
 *        calls will not overlap until all non-privileged ports have been
 *        exhausted.
 *
 * @return A collection of ports.
 */
TestPorts get_test_ports();

/* Implement this method in test-cases. */
void test();
