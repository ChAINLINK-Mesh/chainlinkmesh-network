#pragma once

#include "node.hpp"

#include <map>
#include <mutex>
#include <optional>

/**
 * @brief The class representing a node's peers.
 *
 *        Safe for concurrent access, and use across different threads.
 */
class Peers {
public:
	/**
	 * @brief Default-constructs a Peers list with no nodes.
	 *
	 */
	Peers() = default;

	/**
	 * @brief Copy-constructs from another Peers list.
	 *
	 *        Well-defined even for concurrent accesses.
	 *
	 * @param other The other Peers list.
	 */
	Peers(const Peers& other);

	/**
	 * @brief Move-constructs from another Peers list.
	 *
	 *        Not well-defined for concurrent accesses to the object being moved.
	 *
	 * @param other The other Peers list.
	 */
	Peers(Peers&& other) noexcept;

	/**
	 * @brief Constructs a Peers list from the given nodes.
	 *
	 * @param nodes The nodes to initially add to the peers list.
	 */
	Peers(const std::vector<Node>& nodes);

	/**
	 * @brief Copy-assigns another Peers list to this.
	 *
	 *        Well-defined even for concurrent accesses to this and the other Peer
	 * list.
	 *
	 * @param other The other Peers list.
	 */
	Peers& operator=(Peers& other);

	/**
	 * @brief Move-assigns this to another Peers list.
	 *
	 *        Not well-defined for concurrent accesses to the object being moved.
	 *
	 * @param other The other Peers list.
	 */
	Peers& operator=(Peers&& other) noexcept;

	/**
	 * @brief Adds a node to the list of peers.
	 *
	 *        Will not update existing nodes.
	 *
	 * @param node The peer node to add.
	 */
	void add_peer(Node node);

	/**
	 * @brief Updates a node in the list of peers.
	 *
	 *        Will add non-existant nodes.
	 *
	 * @param node The peer node to update.
	 */
	void update_peer(Node node);

	/**
	 * @brief Gets a peer from a node's ID.
	 *
	 * @param nodeID The ID of the node to return.
	 * @return Either the node if found, or std::nullopt.
	 */
	std::optional<Node> get_peer(std::uint64_t nodeID) const;

	/**
	 * @brief Gets all peers.
	 *
	 * @return A vector of all peer nodes known.
	 */
	std::vector<Node> get_peers() const;

	/**
	 * @brief Deletes a node from the list of peers.
	 *
	 * @param nodeID The ID of the node to delete.
	 */
	void delete_peer(std::uint64_t nodeID);

protected:
	mutable std::mutex nodesMutex;
	std::map<std::uint64_t, Node> nodes;
};
