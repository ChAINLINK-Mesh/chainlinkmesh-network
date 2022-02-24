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
TestPorts get_test_ports();

/* Implement this method in test-cases. */
void test();
