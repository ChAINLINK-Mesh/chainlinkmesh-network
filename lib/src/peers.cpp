#include "peers.hpp"

#include <Poco/Net/IPAddress.h>
#include <functional>
#include <stack>
#include <variant>

Peers::Peers(const Peers& other) {
	// Guard against assigning to ourselves.
	std::unique_lock<std::mutex> otherNodesLock{ other.nodesMutex };
	this->nodes = other.nodes;
	this->children = other.children;
}

Peers::Peers(Peers&& other) noexcept
    : nodes{ std::move(other.nodes) }, children{ std::move(other.children) } {}

Peers::Peers(const std::vector<Node>& nodes) {
	for (const auto& node : nodes) {
		[[maybe_unused]] auto [_, inserted] =
		    this->nodes.insert(std::make_pair(node.id, node));

		// If we didn't insert, then we have duplicate node IDs, which doesn't make
		// sense.
		assert(inserted);

		if (node.parent.has_value()) {
			this->children[node.parent.value()].push_back(node.id);
		}
	}
}

Peers& Peers::operator=(Peers& other) {
	// Guard against assigning to ourselves.
	if (this != &other) {
		// Acquires locks with deadlock-avoidance algorithm.
		std::scoped_lock nodesLock{ nodesMutex, other.nodesMutex };
		this->nodes = other.nodes;
		this->children = other.children;
	}

	return *this;
}

Peers& Peers::operator=(Peers&& other) noexcept {
	// Guard against assigning to ourselves.
	if (this != &other) {
		std::unique_lock<std::mutex> thisNodesLock{ nodesMutex };
		this->nodes = std::move(other.nodes);
		this->children = other.children;
	}

	return *this;
}

bool Peers::add_peer(Node node) {
	assert(validate_peer(node));
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	auto [_, inserted] =
	    this->nodes.insert(std::make_pair(node.id, std::move(node)));

	if (inserted && node.parent.has_value()) {
		this->children[node.parent.value()].push_back(node.id);
	}

	return inserted;
}

void Peers::update_peer(Node node) {
	assert(validate_peer(node));
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	auto [_, inserted] = this->nodes.insert_or_assign(node.id, std::move(node));

	if (inserted && node.parent.has_value()) {
		this->children[node.parent.value()].push_back(node.id);
	}
}

void Peers::reset_peers(const std::vector<Node>& peers) {
	// Check all nodes are valid
	for (const auto& node : peers) {
		assert(validate_peer(node));
	}

	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	nodes = {};
	children = {};

	for (const auto& node : peers) {
		auto [_, inserted] = nodes.emplace(node.id, node);

		if (inserted && node.parent.has_value()) {
			this->children[node.parent.value()].push_back(node.id);
		}
	}
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

std::vector<Node> Peers::get_neighbour_peers(std::uint64_t nodeID) const {
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	const auto nodeChildrenIter = children.find(nodeID);

	if (nodeChildrenIter == children.end()) {
		return {};
	}

	const auto& nodeChildren = nodeChildrenIter->second;

	std::vector<Node> neighbours{};
	neighbours.reserve(nodeChildren.size());

	const auto& nodes = this->nodes;
	std::transform(nodeChildren.begin(), nodeChildren.end(),
	               std::back_inserter(neighbours),
	               [&nodes](std::uint64_t n) { return nodes.at(n); });

	if (const auto thisNode = nodes.at(nodeID); thisNode.parent.has_value()) {
		neighbours.push_back(nodes.at(thisNode.parent.value()));
	}

	return neighbours;
}

std::optional<Node> Peers::delete_peer(const std::uint64_t nodeID) {
	std::unique_lock<std::mutex> peersLock{ nodesMutex };

	if (const auto peerIter = nodes.find(nodeID); peerIter != nodes.end()) {
		auto peer = std::move(peerIter->second);

		// Get rid of this peer in the parent's list of children.
		if (peer.parent.has_value()) {
			auto& children = this->children[peer.parent.value()];
			std::erase(children, peer.id);
		}

		nodes.erase(nodeID);
		return peer;
	}

	return std::nullopt;
}

std::optional<std::vector<X509_RAII>>
Peers::get_certificate_chain(std::uint64_t nodeID) {
	// Don't synchronise accesses to peers list, as this is inherent to the
	// get_peer() call.

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
	       (!peer.connectionDetails.has_value() ||
	        static_cast<bool>(peer.connectionDetails->wireGuardHost)) &&
	       peer.controlPlaneCertificate != nullptr;
}
