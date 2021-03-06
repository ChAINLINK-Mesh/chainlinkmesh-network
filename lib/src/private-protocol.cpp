#include "private-protocol.hpp"
#include "certificates.hpp"
#include "private-protocol_generated.h"
#include "types.hpp"
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
}

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
		if (!VerifySizePrefixedMessageBuffer(verifier)) {
			return std::nullopt;
		}

		MessageT message{};
		GetSizePrefixedMessage(bytes.data())->UnPackTo(&message);

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

			// Continue even if we have a node's cryptographic details but not their
			// connection details, since they may have already connected to us
			// (knowing our details)

			const auto result =
			    PrivateProtocolClient{ neighbour }.inform_about_new_peer(selfNode,
			                                                             node);

			if (!successful(result)) {
				try {
					throw get_error(result);
				} catch (std::exception& err) {
					std::cerr << "Error when informing neighbour about new peer: "
					          << err.what() << "\n";
				} catch (...) {
					std::cerr
					    << "Unknown error when informing neighbour about new peer.\n";
				}
			} else if (const auto response = get_expected(result);
			           response.command.type == Command_ErrorCommand) {
				std::cerr << "Neighbour reported error after informing about new peer: "
				          << response.command.AsErrorCommand()->error << "\n";
			}
		}
	}

	void PrivateProtocolManager::accept_peer_revocation(
	    const std::uint64_t originator, const std::uint64_t peerID,
	    const std::uint64_t revokingNode, const std::string& signature) {
		this->peers->delete_peer(peerID);

		for (const auto& neighbour : peers->get_neighbour_peers(selfNode.id)) {
			// Don't notify the originator, nor the one doing the revocation, nor the
			// peer being revoked.
			if (neighbour.id == originator || neighbour.id == peerID ||
			    neighbour.id == revokingNode) {
				continue;
			}

			if (!neighbour.connectionDetails.has_value()) {
				continue;
			}

			PrivateProtocolClient{ neighbour }.revoke_peer(selfNode, peerID,
			                                               revokingNode, signature);
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

			if (peerInformResp.command.type == Command_ErrorCommand) {
				return std::make_exception_ptr(std::runtime_error{
				    "Received error response when requesting specific peer: " +
				    peerInformResp.command.AsErrorCommand()->error });
			}
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
			Host wireGuardHost = Host{ command.connection_details->wireguard_address,
				                         Node::DEFAULT_WIREGUARD_PORT };

			nodeConnection = {
				.controlPlanePort = command.connection_details->private_proto_port,
				.wireGuardHost = wireGuardHost,
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
		fbb.FinishSizePrefixed(command.Pack(fbb));
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

	PrivateConnection::PrivateConnection(const Poco::Net::StreamSocket& socket,
	                                     PrivateProtocolManager& parent)
	    : Poco::Net::TCPServerConnection{ socket }, parent{ parent } {}

	void PrivateConnection::run() {
		static_assert(MAX_PACKET_SIZE <= std::numeric_limits<int>::max());

		ByteString responseBytes(MAX_PACKET_SIZE, '\0');
		auto bytesReceived = socket().receiveBytes(
		    responseBytes.data(), static_cast<int>(responseBytes.size()));
		// Flatbuffers uses first 4 bytes for the size prefix.
		// If we don't even receive that much, then reject.
		if (bytesReceived < static_cast<int>(sizeof(flatbuffers::uoffset_t))) {
			send_error("Packet too small");
			return;
		}

		const auto expectedSize =
		    flatbuffers::GetPrefixedSize(responseBytes.data()) +
		    sizeof(flatbuffers::uoffset_t);

		if (expectedSize > MAX_PACKET_SIZE) {
			send_error("Message too large");
			return;
		}

		if (bytesReceived < static_cast<int>(expectedSize)) {
			socket().setReceiveTimeout(RECEIVE_TIMEOUT);
		}

		std::uint16_t totalResponseBytes = bytesReceived;

		// While we have more bytes to wait for.
		while (expectedSize > totalResponseBytes) {
			try {
				bytesReceived = socket().receiveBytes(
				    responseBytes.data() + totalResponseBytes,
				    static_cast<int>(responseBytes.size() - totalResponseBytes));
			} catch (Poco::TimeoutException& /* ignored */) {
				send_error("Transmit rate too slow");
				return;
			}

			totalResponseBytes += bytesReceived;
		}

		std::span<const std::uint8_t> bufData{ responseBytes.data(),
			                                     totalResponseBytes };

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
		fbb.FinishSizePrefixed(packet->command.Pack(fbb));
		const auto fbbBuffer = fbb.GetBufferSpan();

		const auto signatureMatches = CertificateManager::check_signature(
		    originator->controlPlanePublicKey,
		    std::span<const std::uint8_t>{ fbbBuffer.data(), fbbBuffer.size() },
		    packet->signature);

		if (!signatureMatches.has_value() || !signatureMatches.value()) {
			send_error("Could not confirm signature");
			return;
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
			case Command_PeerRevocationCommand:
				handle_peer_revocation(packet.value());
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

	void PrivateConnection::send_ack() {
		AckCommandT ackCommand{};
		PrivateProtocol::CommandUnion command{};
		command.Set(ackCommand);

		// If we fail to sign the ack message, don't send it.
		if (auto message = PrivateProtocolManager::command_to_message(
		        parent.selfNode, command)) {
			PrivateProtocolClient::send_message_nowait(socket(), message.value());
		}
	}

	void PrivateConnection::handle_peer_inform(
	    const PrivateProtocol::MessageT& message) {
		assert(message.command.type == Command_PeerInformCommand);

		const auto& peerInform = message.command.AsPeerInformCommand();

		auto optNode =
		    PrivateProtocolManager::convert_peer_inform_to_node(*peerInform);

		if (std::holds_alternative<std::exception_ptr>(optNode)) {
			try {
				std::rethrow_exception(std::get<std::exception_ptr>(optNode));
			} catch (const std::runtime_error& err) {
				send_error(err.what());
			} catch (...) {
				// Some other unspecified error, so just fail the response.
			}
			return;
		}

		// Get issuer, and verify that they are the listed parent.
		auto& node = std::get<Node>(optNode);

		if (X509_self_signed(node.controlPlaneCertificate.get(), 1) == 1) {
			throw std::runtime_error{
				"Peer inform announces self-signed certificate"
			};
		}

		const X509_NAME* issuer =
		    X509_get_issuer_name(node.controlPlaneCertificate.get());

		if (issuer == nullptr) {
			throw std::runtime_error{ "Couldn't discover peer-inform's issuer" };
		}

		const auto issuerID =
		    CertificateManager::get_subject_attribute(issuer, NID_serialNumber);

		if (issuerID.size() != 1) {
			throw std::runtime_error{ "Failed to get a single issuer node ID" };
		}

		// Will throw if ID cannot be converted to an integer
		const auto issuerIDNum = std::stoull(issuerID[0]);

		if (issuerIDNum != node.parent) {
			throw std::runtime_error{
				"Peer announcement's parent doesn't match its certificate's issuer"
			};
		}

		// const auto issuerCertChain =
		//     parent.peers->get_certificate_chain(issuerIDNum);
		const auto knownIssuerDetails = parent.peers->get_peer(issuerIDNum);

		if (!knownIssuerDetails.has_value()) {
			throw std::runtime_error{ "Issuer is unknown" };
		}

		const auto knownIssuerPublicKey =
		    CertificateManager::get_certificate_pubkey(
		        knownIssuerDetails->controlPlaneCertificate);

		// Expect any certificate decoding to have been validated for existing
		// peers.
		assert(knownIssuerPublicKey.has_value());

		if (int issuerCertificateVeracity = X509_verify(
		        node.controlPlaneCertificate.get(), knownIssuerPublicKey->get());
		    issuerCertificateVeracity < 1) {
			throw std::runtime_error{
				std::string{ "Issuer has different public key to known public key: " } +
				std::to_string(issuerCertificateVeracity)
			};
		}

		// Send Ack response first, so that the peer can continue sending out its
		// own messages.
		AckCommandT ackCommand{};
		CommandUnion ackCommandUnion{};
		ackCommandUnion.Set(ackCommand);

		const auto ack = PrivateProtocolManager::command_to_message(
		    parent.selfNode, ackCommandUnion);

		// Error to not be able to Ack, but not the responsibility of the sending
		// node, so don't inform.
		if (ack.has_value()) {
			PrivateProtocolClient{ socket() }.send_message_nowait(ack.value());
		}

		parent.accept_peer_request(message.originator, node);
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

	void PrivateConnection::handle_peer_revocation(
	    const PrivateProtocol::MessageT& message) {
		assert(message.command.type == Command_PeerRevocationCommand);
		const auto* const revocation = message.command.AsPeerRevocationCommand();
		const auto revokingNode = parent.peers->get_peer(revocation->revoking_node);

		if (!revokingNode.has_value()) {
			send_error("Unknown revoking node");
			return;
		}

		const auto peerIDStr = std::to_string(revocation->peer_id);

		if (const auto signatureMatches =
		        GenericCertificateManager<char>::check_signature(
		            revokingNode->controlPlanePublicKey, peerIDStr,
		            revocation->signature);
		    !signatureMatches.has_value() || !signatureMatches.value()) {
			send_error("Revocation attributed to wrong node");
			return;
		}

		const auto peerCertChain =
		    parent.peers->get_certificate_chain(revocation->peer_id);

		// We don't know the node being revoked, but so no action needs to be taken.
		if (!peerCertChain.has_value()) {
			send_ack();
			return;
		}

		for (const auto& peerCert : peerCertChain.value()) {
			// Non-owning copy of the subject name.
			auto* const peerName = X509_get_subject_name(peerCert.get());
			const auto peerID =
			    CertificateManager::get_subject_attribute(peerName, NID_serialNumber);

			// If the peerCert doesn't have a single valid ID, ignore it.
			// Shouldn't ever be in this position, as all certificates should have
			// already been filtered.
			if (peerID.size() != 1) {
				continue;
			}

			// We only want to compare details of the revoking node.
			if (peerID[0] != std::to_string(revocation->revoking_node)) {
				continue;
			}

			// We have found a node in the ancestry of the revoked node, and their
			// revocation is cryptographically correct.
			parent.accept_peer_revocation(message.originator, revocation->peer_id,
			                              revocation->revoking_node,
			                              revocation->signature);
			send_ack();
			return;
		}

		send_error("Unable to verify revocation authorisation");
	}

	PrivateProtocolClient::PrivateProtocolClient(Node peer)
	    : socket{ OptionallyOwned<Poco::Net::StreamSocket>::make(
		        Poco::Net::SocketAddress{
		            peer.controlPlaneIP,
		            peer.connectionDetails.has_value()
		                ? peer.connectionDetails->controlPlanePort
		                : PrivateProtocol::DEFAULT_CONTROL_PLANE_PORT,
		        }) } {}

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

	Expected<MessageT> PrivateProtocolClient::revoke_peer(
	    const SelfNode& self, const std::uint64_t peerID,
	    const std::uint64_t revokingNode, const std::string& signature) {
		PeerRevocationCommandT revocation{};
		revocation.peer_id = peerID;
		revocation.revoking_node = revokingNode;
		revocation.signature = signature;

		CommandUnion command{};
		command.Set(revocation);

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
		return send_message_nowait(socket, message);
	}

	Expected<MessageT>
	PrivateProtocolClient::send_message(Poco::Net::StreamSocket& socket,
	                                    const MessageT& message) {
		const auto sendResult = send_message_nowait(socket, message);

		if (!successful(sendResult)) {
			return get_error(sendResult);
		}

		try {
			socket.setReceiveTimeout(RECEIVE_TIMEOUT);
			ByteString responseBytes(MAX_PACKET_SIZE, '\0');
			int bytesReceived = 0;

			bytesReceived = socket.receiveBytes(
			    responseBytes.data(), static_cast<int>(responseBytes.size()));

			// Flatbuffers uses first 4 bytes for the size prefix.
			// If we don't even receive that much, then reject.
			if (bytesReceived < static_cast<int>(sizeof(flatbuffers::uoffset_t))) {
				return std::make_exception_ptr(
				    std::runtime_error{ "Response packet too small" });
			}

			const auto expectedSize =
			    flatbuffers::GetPrefixedSize(responseBytes.data()) +
			    sizeof(flatbuffers::uoffset_t);

			if (expectedSize > MAX_PACKET_SIZE) {
				return std::make_exception_ptr(
				    std::runtime_error{ "Response message too large" });
			}

			while (bytesReceived < static_cast<int>(expectedSize)) {
				try {
					bytesReceived += socket.receiveBytes(
					    responseBytes.data() + bytesReceived,
					    static_cast<int>(responseBytes.size() - bytesReceived));
				} catch (Poco::TimeoutException& /* ignored */) {
					return std::make_exception_ptr(std::runtime_error{
					    "Timeout when waiting for response message" });
				}
			}

			const std::span<const std::uint8_t> bufData{
				reinterpret_cast<const std::uint8_t*>(responseBytes.data()),
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
		fbb.FinishSizePrefixed(Message::Pack(fbb, &message));

		const auto fbbBuffer = fbb.GetBufferSpan();
		assert(fbbBuffer.size_bytes() < std::numeric_limits<int>::max());

		try {
			socket.sendBytes(fbbBuffer.data(),
			                 static_cast<int>(fbbBuffer.size_bytes()));
		} catch (Poco::Net::NetException& e) {
			return std::make_exception_ptr(e);
		}

		return std::nullopt;
	}
} // namespace PrivateProtocol
