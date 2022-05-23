#include "private-protocol.hpp"
#include "certificates.hpp"
#include "private-protocol_generated.h"
#include "utilities.hpp"
#include "wireguard.hpp"

#include <Poco/Net/NetException.h>
#include <Poco/Net/StreamSocket.h>
#include <Poco/Net/TCPServerConnection.h>
#include <exception>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>
#include <variant>

extern "C" {
#include <openssl/obj_mac.h>
#include <openssl/x509.h>

#include <memory>
};

namespace PrivateProtocol {
	PrivateProtocolManager::PrivateProtocolManager(Configuration config)
	    : controlPlanePort{ config.controlPlanePort },
	      peers{ std::move(config.peers) }, selfNode{ std::move(
		                                          config.selfNode) } {
		// Prevent nullptr being passed.
		assert(peers);
	}

	std::optional<MessageT> PrivateProtocolManager::decode_packet(
	    const std::span<const std::uint8_t>& bytes) {
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

	void
	PrivateProtocolManager::accept_peer_request(const std::uint64_t originator,
	                                            const Node& node) {
		this->peers->update_peer(node);

		for (const auto& neighbour : peers->get_neighbour_peers(selfNode.id)) {
			if (neighbour.id == originator || neighbour.id == node.id) {
				continue;
			}

			// If we have a node's cryptographic details but not their connection
			// details, then don't send to them.
			if (!neighbour.connectionDetails.has_value()) {
				continue;
			}

			inform_node_about_new_peer(neighbour, node);
		}
	}

	Expected<std::vector<Node>>
	PrivateProtocolManager::get_peers(const SelfNode& self, const Node& other,
	                                  const std::vector<Node>& knownNodes) {
		auto peerListRespExpected =
		    PrivateProtocolClient{ other }.request_peer_list(self);

		if (std::holds_alternative<std::exception_ptr>(peerListRespExpected)) {
			return std::get<std::exception_ptr>(peerListRespExpected);
		}

		const auto peerListResp = std::get<MessageT>(peerListRespExpected);

		if (peerListResp.command.type != Command_PeerListResponseCommand) {
			return std::make_exception_ptr(std::runtime_error{
			    "Received error response when requesting peer list" });
		}

		const auto* peerList = peerListResp.command.AsPeerListResponseCommand();
		std::set<std::uint64_t> peerIDs{};

		for (const auto peer : peerList->peers) {
			if (peerIDs.contains(peer)) {
				return std::make_exception_ptr(std::runtime_error{
				    "Response peer list contains duplicate peers" });
			}

			peerIDs.insert(peer);
		}

		// Map from node ID -> peers for which we already have known details.
		std::map<std::uint64_t, Node> knownPeerMap{};
		// Map from node ID -> peers for which now exist in the network.
		std::map<std::uint64_t, Node> peerMap{};

		for (const auto& knownNode : knownNodes) {
			knownPeerMap.emplace(knownNode.id, knownNode);
		}

		for (const auto peer : peerList->peers) {
			if (const auto knownPeerIter = knownPeerMap.find(peer);
			    knownPeerIter != knownPeerMap.end()) {
				peerMap.emplace(peer, knownPeerIter->second);
				continue;
			}

			auto peerInformExpected =
			    PrivateProtocolClient{ other }.request_peer(self, peer);

			if (std::holds_alternative<std::exception_ptr>(peerInformExpected)) {
				return std::get<std::exception_ptr>(peerInformExpected);
			}

			const auto peerInformResp = std::get<MessageT>(peerInformExpected);

			if (peerInformResp.command.type != Command_PeerInformCommand) {
				return std::make_exception_ptr(std::runtime_error{
				    "Received error response when requesting specific peer" });
			}

			const auto* const peerInform =
			    peerInformResp.command.AsPeerInformCommand();
			const auto nodeExpected =
			    PrivateProtocolManager::convert_peer_inform_to_node(*peerInform);

			if (std::holds_alternative<std::exception_ptr>(nodeExpected)) {
				return std::get<std::exception_ptr>(nodeExpected);
			}

			const auto node = std::get<Node>(nodeExpected);

			peerMap.emplace(node.id, node);
		}

		// Check all peers for unknown parents.
		for (auto& [_, peer] : peerMap) {
			if (peer.parent.has_value() && !peerMap.contains(peer.parent.value())) {
				return std::make_exception_ptr(std::runtime_error{
				    "Peer in response list doesn't have a valid parent" });
			}
		}

		std::vector<Node> peers{};
		std::transform(peerMap.begin(), peerMap.end(), std::back_inserter(peers),
		               [](auto& keyPair) { return keyPair.second; });

		return peers;
	}

	PeerInformCommandT
	PrivateProtocolManager::convert_node_to_peer_inform(const Node& peer) {
		PeerInformCommandT peerListing{};
		peerListing.peer_id = peer.id;
		peerListing.certificate = GenericCertificateManager<char>::encode_pem(
		    peer.controlPlaneCertificate);
		peerListing.parent = to_flatbuffers(peer.parent);

		if (peer.connectionDetails) {
			peerListing.connection_details =
			    std::make_unique<PeerConnectionDetailsT>();
			peerListing.connection_details->wireguard_address =
			    static_cast<std::string>(peer.connectionDetails->wireGuardHost);
			peerListing.connection_details->private_proto_port =
			    peer.connectionDetails->controlPlanePort;
		}

		return peerListing;
	}

	Expected<Node> PrivateProtocolManager::convert_peer_inform_to_node(
	    const PeerInformCommandT& command) {
		const auto peerCertificateChain =
		    GenericCertificateManager<char>::decode_pem_certificate_chain(
		        command.certificate);

		auto certificateError = []() {
			return std::make_exception_ptr(
			    std::runtime_error{ "Could not decode peer certificate chain" });
		};

		if (!peerCertificateChain.has_value()) {
			return certificateError();
		}

		const auto peerCertificate = peerCertificateChain->back();
		const auto peerPublicKey =
		    CertificateManager::get_certificate_pubkey(peerCertificate);

		if (!peerPublicKey.has_value()) {
			return certificateError();
		}

		X509_NAME* peerSubject = X509_get_subject_name(peerCertificate.get());

		if (peerSubject == nullptr) {
			return std::make_exception_ptr(
			    std::runtime_error{ "Could not decode peer certificate chain" });
		}

		const auto wireguardPublicKeyB64Str =
		    CertificateManager::get_subject_attribute(peerSubject, NID_userId);

		if (wireguardPublicKeyB64Str.size() != 1 ||
		    wireguardPublicKeyB64Str[0].size() !=
		        base64_encoded_character_count(
		            AbstractWireGuardManager::WG_KEY_SIZE)) {
			return certificateError();
		}

		const auto wireguardPublicKeyStr =
		    base64_decode(wireguardPublicKeyB64Str[0]);

		if (!wireguardPublicKeyStr.has_value()) {
			return certificateError();
		}

		AbstractWireGuardManager::Key wireGuardPublicKey{};
		std::copy(wireguardPublicKeyStr->begin(), wireguardPublicKeyStr->end(),
		          wireGuardPublicKey.begin());

		const auto peerControlPlaneIP = Node::get_control_plane_ip(command.peer_id);

		std::optional<NodeConnection> nodeConnection{};

		if (command.connection_details != nullptr) {
			Host wireGuardHost =
			    Host{ command.connection_details->wireguard_address };

			nodeConnection = {
				.controlPlanePort = command.connection_details->private_proto_port,
				.wireGuardHost = wireGuardHost,
				.wireGuardPort =
				    wireGuardHost.port().value_or(Node::DEFAULT_WIREGUARD_PORT),
			};
		}

		return Node{
			.id = command.peer_id,
			.controlPlanePublicKey = peerPublicKey.value(),
			.wireGuardPublicKey = wireGuardPublicKey,
			.controlPlaneIP = peerControlPlaneIP,
			.connectionDetails = nodeConnection,
			.controlPlaneCertificate = peerCertificate,
			.parent = command.parent,
		};
	}

	std::optional<MessageT>
	PrivateProtocolManager::command_to_message(const SelfNode& self,
	                                           const CommandUnion& command) {
		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(command.Pack(fbb));
		const auto fbbBuffer = fbb.GetBufferSpan();

		const auto signature = CertificateManager::sign_data(
		    self.controlPlanePrivateKey,
		    std::span<std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() });

		// If we fail to sign the error message, don't send it.
		if (!signature.has_value()) {
			return std::nullopt;
		}

		MessageT message{};
		message.originator = self.id;
		message.command = command;
		message.signature = signature.value();

		return message;
	}

	void PrivateProtocolManager::inform_node_about_new_peer(const Node& node,
	                                                        const Node& newPeer) {
		// Requires knowing connection details to contact 'node'.
		assert(node.connectionDetails);

		PrivateProtocolClient{ node }.inform_about_new_peer(selfNode, newPeer);
	}

	PrivateConnection::PrivateConnection(const Poco::Net::StreamSocket& socket,
	                                     PrivateProtocolManager& parent)
	    : Poco::Net::TCPServerConnection{ socket }, parent{ parent } {}

	void PrivateConnection::run() {
		Poco::Buffer<char> buf{ MAX_PACKET_SIZE };
		const auto bytes = socket().receiveBytes(buf);
		const std::span<const std::uint8_t> bufData{
			reinterpret_cast<const std::uint8_t*>(buf.begin()), buf.size()
		};

		const auto packet = PrivateProtocolManager::decode_packet(bufData);

		if (!packet) {
			send_error("Could not decode packet");
			return;
		}

		const auto originator = parent.peers->get_peer(packet->originator);

		if (!originator.has_value()) {
			send_error("Unknown origin");
			return;
		}

		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(packet->command.Pack(fbb));
		const auto fbbBuffer = fbb.GetBufferSpan();

		const auto signatureMatches = CertificateManager::check_signature(
		    originator->controlPlanePublicKey,
		    std::span<const std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() },
		    packet->signature);

		if (!signatureMatches.has_value() || !signatureMatches.value()) {
			send_error("Could not confirm signature");
		}

		switch (packet->command.type) {
			case Command_NONE:
				send_error("Unknown command");
				break;
			case Command_PeerInformCommand:
				handle_peer_inform(packet.value());
				break;
			case Command_PeerListCommand:
				handle_peer_list();
				break;
			case Command_PeerListResponseCommand:
				// We didn't request this command, otherwise we would reuse the existing
				// connection.
				send_error("Unexpected Peer List response");
				break;
			case Command_PeerRequestCommand:
				handle_peer_request(packet.value());
				break;
			case Command_ErrorCommand:
				// Don't respond to this. Alternative implementations may have a more
				// advanced error recovery mechanism.
			case Command_AckCommand:
				// Don't need to handle AckCommands, as this indicates a success.
				// Therefore there is nothing more we need to do.
				break;
		}
	}

	void PrivateConnection::send_error(const std::string& errorMsg) {
		ErrorCommandT errorCommand{};
		errorCommand.error = errorMsg;

		PrivateProtocol::CommandUnion command{};
		command.Set(errorCommand);

		// If we fail to sign the error message, don't send it.
		if (auto message = PrivateProtocolManager::command_to_message(
		        parent.selfNode, command)) {
			PrivateProtocolClient::send_message_nowait(socket(), message.value());
		}
	}

	void PrivateConnection::handle_peer_inform(
	    const PrivateProtocol::MessageT& message) {
		assert(message.command.type == Command_PeerInformCommand);

		const auto& peerInform = message.command.AsPeerInformCommand();

		auto node =
		    PrivateProtocolManager::convert_peer_inform_to_node(*peerInform);

		if (std::holds_alternative<std::exception_ptr>(node)) {
			try {
				std::rethrow_exception(std::get<std::exception_ptr>(node));
			} catch (const std::runtime_error& err) {
				send_error(err.what());
			} catch (...) {
				// Some other unspecified error, so just fail the response.
			}
			return;
		}

		parent.accept_peer_request(message.originator, std::get<Node>(node));

		AckCommandT ackCommand{};
		CommandUnion ackCommandUnion{};
		ackCommandUnion.Set(ackCommand);

		const auto ack = PrivateProtocolManager::command_to_message(
		    parent.selfNode, ackCommandUnion);

		// Error, but not the responsibility of the sending node, so don't inform.
		if (!ack.has_value()) {
			return;
		}

		PrivateProtocolClient{ socket() }.send_message_nowait(ack.value());
	}

	void PrivateConnection::handle_peer_list() {
		const auto peers = parent.peers->get_peers();
		PeerListResponseCommandT peerList{};

		for (const auto& peer : peers) {
			peerList.peers.push_back(peer.id);
		}

		CommandUnion command{};
		command.Set(peerList);

		const auto message =
		    PrivateProtocolManager::command_to_message(parent.selfNode, command);

		// If we failed to sign the command, fail.
		if (!message) {
			return;
		}

		PrivateProtocolClient{ socket() }.send_message_nowait(message.value());
	}

	void PrivateConnection::handle_peer_request(
	    const PrivateProtocol::MessageT& message) {
		assert(message.command.type == Command_PeerRequestCommand);
		const auto peer =
		    parent.peers->get_peer(message.command.AsPeerRequestCommand()->peer_id);

		// Don't recursively request from parent. This is likely to add a large
		// amount of protocol overhead, but it could be used to improve
		// synchronisation of node lists between nodes.
		if (!peer.has_value()) {
			send_error("Peer not found");
			return;
		}

		auto peerInform =
		    PrivateProtocolManager::convert_node_to_peer_inform(peer.value());

		CommandUnion command{};
		command.Set(peerInform);

		auto response =
		    PrivateProtocolManager::command_to_message(parent.selfNode, command);

		// If we failed to sign the response, then just fail.
		if (!response) {
			return;
		}

		PrivateProtocolClient{ socket() }.send_message_nowait(response.value());
	}

	PrivateProtocolClient::PrivateProtocolClient(Node peer)
	    : socket{ OptionallyOwned<Poco::Net::StreamSocket>::make(
		        Poco::Net::SocketAddress{
		            peer.controlPlaneIP,
		            peer.connectionDetails->controlPlanePort,
		        }) } {
		assert(peer.connectionDetails);
	}

	PrivateProtocolClient::PrivateProtocolClient(Poco::Net::StreamSocket& socket)
	    : socket{ socket } {}

	Expected<MessageT>
	PrivateProtocolClient::inform_about_new_peer(const SelfNode& self,
	                                             const Node& newPeer) {
		auto peerInform =
		    PrivateProtocolManager::convert_node_to_peer_inform(newPeer);

		CommandUnion command{};
		command.Set(peerInform);

		const auto message =
		    PrivateProtocolManager::command_to_message(self, command);

		if (!message.has_value()) {
			return std::make_exception_ptr(
			    std::runtime_error{ "Failed to sign message" });
		}

		return send_message(message.value());
	}

	Expected<MessageT>
	PrivateProtocolClient::request_peer_list(const SelfNode& self) {
		PeerListCommandT peerListReq{};

		CommandUnion command{};
		command.Set(peerListReq);

		auto message = PrivateProtocolManager::command_to_message(self, command);

		if (!message.has_value()) {
			return std::make_exception_ptr(
			    std::runtime_error{ "Failed to sign message" });
		}

		return send_message(message.value());
	}

	Expected<MessageT> PrivateProtocolClient::request_peer(const SelfNode& self,
	                                                       std::uint64_t peerID) {
		PeerRequestCommandT request{};
		request.peer_id = peerID;

		CommandUnion command{};
		command.Set(request);

		const auto message =
		    PrivateProtocolManager::command_to_message(self, command);

		if (!message.has_value()) {
			return std::make_exception_ptr(
			    std::runtime_error{ "Failed to sign message" });
		}

		return send_message(message.value());
	}

	Expected<MessageT>
	PrivateProtocolClient::send_message(const MessageT& message) {
		return send_message(socket, message);
	}

	Expected<void>
	PrivateProtocolClient::send_message_nowait(const MessageT& message) {
		send_message_nowait(socket, message);
		return std::nullopt;
	}

	Expected<MessageT>
	PrivateProtocolClient::send_message(Poco::Net::StreamSocket& socket,
	                                    const MessageT& message) {
		try {
			send_message_nowait(socket, message);
			Poco::FIFOBuffer buffer{ MAX_PACKET_SIZE };
			int bytesReceived = socket.receiveBytes(buffer);
			const std::span<const std::uint8_t> bufData{
				reinterpret_cast<const std::uint8_t*>(buffer.begin()),
				static_cast<std::size_t>(bytesReceived)
			};

			const auto response = PrivateProtocolManager::decode_packet(bufData);

			if (!response.has_value()) {
				return std::make_exception_ptr(
				    std::runtime_error{ "Could not decode response packet" });
			}

			return response.value();
		} catch (Poco::Net::NetException& e) {
			return std::make_exception_ptr(e);
		}
	}

	Expected<void>
	PrivateProtocolClient::send_message_nowait(Poco::Net::StreamSocket& socket,
	                                           const MessageT& message) {
		flatbuffers::FlatBufferBuilder fbb{};
		fbb.Finish(Message::Pack(fbb, &message));

		const auto fbbBuffer = fbb.GetBufferSpan();
		assert(fbbBuffer.size_bytes() < std::numeric_limits<int>::max());

		try {
			socket.sendBytes(fbb.GetBufferSpan().data(),
			                 static_cast<int>(fbb.GetBufferSpan().size_bytes()));
		} catch (Poco::Net::NetException& e) {
			return std::make_exception_ptr(e);
		}

		return std::nullopt;
	}
} // namespace PrivateProtocol
