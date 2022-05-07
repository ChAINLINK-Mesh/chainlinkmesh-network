#pragma once

#include <Poco/Net/IPAddress.h>

class NetlinkManager {
public:
	static bool add_address(const std::string& interfaceName,
	                        const Poco::Net::IPAddress& address);
	static bool set_link_up(const std::string& interfaceName);
};
