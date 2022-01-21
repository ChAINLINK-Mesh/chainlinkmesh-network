#pragma once
#include <string>
#include <Poco/Net/IPAddress.h>

struct Node {
	std::uint64_t id;
	std::string publicKey;
	Poco::Net::IPAddress meshIP;
};
