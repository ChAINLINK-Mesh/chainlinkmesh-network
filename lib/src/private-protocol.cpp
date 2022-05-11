#include "private-protocol.hpp"
#include "certificates.hpp"
#include "flatbuffers/flatbuffer_builder.h"
#include "private-protocol_generated.h"

#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/TCPServerConnection.h>

namespace PrivateProtocol {
	PrivateProtocolManager::PrivateProtocolManager(Configuration config)
	    : controlPlanePort{ config.controlPlanePort },
	      peers{ std::move(config.peers) }, selfNode{ std::move(
		                                          config.selfNode) } {
		// Prevent nullptr being passed.
		assert(peers);
	}

	std::optional<MessageT>
	PrivateProtocolManager::decode_packet(const std::span<std::uint8_t>& bytes) {
		flatbuffers::Verifier verifier{ bytes.data(), bytes.size() };
		if (!VerifyMessageBuffer(verifier)) {
			return std::nullopt;
		}

		MessageT message{};
		GetMessage(bytes.data())->UnPackTo(&message);

		return message;
	}

	std::unique_ptr<Poco::Net::TCPServer>
	PrivateProtocolManager::start(const Poco::Net::ServerSocket& serverSocket,
	                              Poco::Net::TCPServerParams::Ptr params) {
		auto server = std::make_unique<Poco::Net::TCPServer>(
		    new ConnectionFactory(*this), serverSocket, std::move(params));
		server->start();

		return server;
	}

	PrivateProtocolManager::ConnectionFactory::ConnectionFactory(
	    PrivateProtocolManager& parent)
	    : parent{ parent } {}

	Poco::Net::TCPServerConnection*
	PrivateProtocolManager::ConnectionFactory::createConnection(
	    const Poco::Net::StreamSocket& socket) {
		return new PrivateConnection{ socket, parent };
	}

	bool
	PrivateProtocolManager::accept_peer_request(const std::uint64_t originator,
	                                            const Node& node) {
		const auto addedPeer = this->peers->add_peer(node);

		if (addedPeer) {
			for (const auto& neighbour : peers->get_neighbour_peers(selfNode.id)) {
				if (neighbour.id == originator || neighbour.id == node.id) {
					continue;
				}

				inform_node_about_new_peer(neighbour.id, node);
			}
		}

		return addedPeer;
	}

	void PrivateProtocolManager::inform_node_about_new_peer(std::uint64_t nodeID,
	                                                        const Node& peer) {
		PeerInformCommandT peerInformCommand{
			.peer_id = peer.id,
			.certificate = GenericCertificateManager<char>::encode_pem(
			    peer.controlPlaneCertificate),
			.wireguard_address = static_cast<std::string>(peer.wireGuardHost),
			.private_proto_port = peer.controlPlanePort,
		};

		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(
		    PrivateProtocol::PeerInformCommand::Pack(fbb, &peerInformCommand));
		const auto& fbbBuffer = fbb.GetBufferSpan();

		const auto signature = CertificateManager::sign_data(
		    selfNode.controlPlanePrivateKey,
		    std::span<std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() });

		// If signing the message failed, don't attempt to send message.
		if (!signature.has_value()) {
			return;
		}

		PrivateProtocol::CommandUnion command{};
		command.Set(peerInformCommand);
		MessageT message{ .originator = selfNode.id,
			                .command = command,
			                .signature = signature.value() };
	}

	PrivateConnection::PrivateConnection(const Poco::Net::StreamSocket& socket,
	                                     PrivateProtocolManager& parent)
	    : Poco::Net::TCPServerConnection{ socket }, parent{ parent } {}

	void PrivateConnection::run() {
		throw "TODO: Unimplemented";
	}
} // namespace PrivateProtocol
