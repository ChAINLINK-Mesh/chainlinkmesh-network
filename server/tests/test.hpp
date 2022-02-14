#pragma once

#include "server.hpp"
#include <Poco/Net/SocketAddress.h>

ByteString read_file(const std::string& filename);

struct TestPorts {
	Poco::Net::SocketAddress wireGuardAddress;
	Poco::Net::SocketAddress publicProtoAddress;
	Poco::Net::SocketAddress privateProtoAddress;
};

/* Implement these methods in test-cases. */
void test(Server& server);
Server::Configuration get_config(const TestPorts& testPorts);
