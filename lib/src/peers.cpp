#include "peers.hpp"

#include <Poco/Net/IPAddress.h>
#include <functional>
#include <stack>
#include <variant>

Peers::Peers(const Peers& other) {
	// Guard against assigning to ourselves.
	std::unique_lock<std::mutex> otherNodesLock{ other.nodesMutex };
	this->nodes = other.nodes;
}

Peers::Peers(Peers&& other) noexcept : nodes{ std::move(other.nodes) } {}

Peers::Peers(const std::vector<Node>& nodes) {
	for (const auto& node : nodes) {
		this->nodes.insert(std::make_pair(node.id, node));
	}
}

Peers& Peers::operator=(Peers& other) {
	// Guard against assigning to ourselves.
	if (this != &other) {
		// Acquires locks with deadlock-avoidance algorithm.
		std::scoped_lock nodesLock{ nodesMutex, other.nodesMutex };
		this->nodes = other.nodes;
	}

	return *this;
}

Peers& Peers::operator=(Peers&& other) noexcept {
	// Guard against assigning to ourselves.
	if (this != &other) {
		std::unique_lock<std::mutex> thisNodesLock{ nodesMutex };
		this->nodes = std::move(other.nodes);
	}

	return *this;
}

bool Peers::add_peer(Node node) {
	assert(validate_peer(node));
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	return this->nodes.insert(std::make_pair(node.id, std::move(node))).second;
}

void Peers::update_peer(Node node) {
	assert(validate_peer(node));
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	this->nodes.insert_or_assign(node.id, std::move(node));
}

std::optional<Node> Peers::get_peer(const std::uint64_t nodeID) const {
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	const auto peer = nodes.find(nodeID);

	if (peer != nodes.end()) {
		return peer->second;
	}

	return std::nullopt;
}

std::vector<Node> Peers::get_peers() const {
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	std::vector<Node> peers{};
	peers.reserve(nodes.size());

	for (const auto& [_, node] : nodes) {
		peers.push_back(node);
	}

	return peers;
}

std::optional<Node> Peers::delete_peer(const std::uint64_t nodeID) {
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	if (const auto peerIter = nodes.find(nodeID); peerIter != nodes.end()) {
		auto peer = std::move(peerIter->second);
		nodes.erase(nodeID);
		return peer;
	}

	return std::nullopt;
}

std::optional<std::vector<X509_RAII>>
Peers::get_certificate_chain(std::uint64_t nodeID) {
	std::vector<X509_RAII> certificates{};

	while (const auto& peer = get_peer(nodeID)) {
		certificates.emplace_back(peer->controlPlaneCertificate);

		if (!peer->parent) {
			break;
		}

		nodeID = *peer->parent;
	}

	if (certificates.empty()) {
		return std::nullopt;
	}

	return std::vector<X509_RAII>{ certificates.rbegin(), certificates.rend() };
}

bool Peers::validate_peer(const Node& peer) {
	return peer.controlPlanePublicKey != nullptr &&
	       static_cast<bool>(peer.wireGuardHost) &&
	       peer.controlPlaneCertificate != nullptr;
}
