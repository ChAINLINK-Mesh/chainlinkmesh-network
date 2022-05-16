#include "test.hpp"
#include "literals.hpp"
#include "private-protocol.hpp"
#include "private-protocol_generated.h"

#include <flatbuffers/flatbuffer_builder.h>
#include <limits>

const constexpr std::uint16_t MIN_UNPRIVILEGED_PORT = 2048 + 1;

std::uint16_t get_safe_port();
SelfNode get_self_node();

void create_private_protocol_manager();
void decode_packet();

void test() {
	create_private_protocol_manager();
	decode_packet();
}

void create_private_protocol_manager() {
	[[maybe_unused]] PrivateProtocol::PrivateProtocolManager manager{
		PrivateProtocol::PrivateProtocolManager::Configuration{
		    .controlPlanePort = get_safe_port(),
		    .selfNode = get_self_node(),
		    .peers = std::make_shared<Peers>(),
		},
	};
}

void decode_packet() {
	PrivateProtocol::ErrorCommandT errorMessage{};
	errorMessage.error = "Test error";

	PrivateProtocol::CommandUnion command{};
	command.Set(errorMessage);

	const auto randByte = []() { return static_cast<std::uint8_t>(rand()); };

	PrivateProtocol::MessageT message{};
	message.originator = static_cast<std::uint64_t>(rand());
	message.command = command;
	message.signature = { randByte(), randByte(), randByte(), randByte() };

	flatbuffers::FlatBufferBuilder fbb{};
	fbb.Finish(PrivateProtocol::Message::Pack(fbb, &message));

	const auto fbbBytes = fbb.GetBufferSpan();
	const auto decodedPacket =
	    PrivateProtocol::PrivateProtocolManager::decode_packet(fbbBytes);

	if (!decodedPacket) {
		throw "Failed to decode valid packet";
	}
	if (decodedPacket->originator != message.originator) {
		throw "Failed to decode correct originator ID";
	}
	if (decodedPacket->command.type !=
	    PrivateProtocol::Command::Command_ErrorCommand) {
		throw "Decoded packet as invalid commmand type";
	}
	if (decodedPacket->command.AsErrorCommand()->error != errorMessage.error) {
		throw "Decoded packet with invalid error message";
	}
	if (decodedPacket->signature != message.signature) {
		throw "Decoded packet with invalid signature";
	}
}

std::uint16_t get_safe_port() {
	static std::uint16_t basePort =
	    rand() %
	        (std::numeric_limits<std::uint16_t>::max() - MIN_UNPRIVILEGED_PORT) +
	    MIN_UNPRIVILEGED_PORT;

	return basePort++;
}

SelfNode get_self_node() {
	return SelfNode{
		Node{
		    .id = 987654321ULL,
		    .controlPlanePublicKey = {},
		    .wireGuardPublicKey = {},
		    .controlPlaneIP = Poco::Net::IPAddress{ "10.0.0.1" },
		    .connectionDetails =
		        NodeConnection{
		            .controlPlanePort = PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT,
		            .wireGuardHost = Host{ "127.0.0.1" },
		            .wireGuardPort = Node::DEFAULT_WIREGUARD_PORT,
		        },
		    .controlPlaneCertificate = {},
		    .parent = std::nullopt,
		},
		{},
		{},
		ByteString{ "Testing Key"_uc },
		100,
	};
}
