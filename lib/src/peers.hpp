#pragma once

#include "node.hpp"

#include <map>
#include <mutex>
#include <optional>
#include <vector>

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
	 *        Peer IDs should not duplicated.
	 *
	 * @param nodes The nodes to initially add to the peers list.
	 */
	Peers(const std::vector<Node>& nodes);

	virtual ~Peers() = default;

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
	 *        Expects peer node to be valid.
	 *
	 * @param node The peer node to add.
	 * @return Whether the insertion occurred.
	 */
	virtual bool add_peer(Node node);

	/**
	 * @brief Updates a node in the list of peers.
	 *
	 *        Will add non-existant nodes.
	 *
	 *        Expects peer node to be valid.
	 *
	 * @param node The peer node to update.
	 */
	virtual void update_peer(Node node);

	/**
	 * @brief Resets the list of peers to just the peers specified.
	 *
	 * @param peers The peer list to reset to.
	 */
	virtual void reset_peers(const std::vector<Node>& peers);

	/**
	 * @brief Gets a peer from a node's ID.
	 *
	 * @param nodeID The ID of the node to return.
	 * @return Either the node if found, or std::nullopt.
	 */
	virtual std::optional<Node> get_peer(std::uint64_t nodeID) const;

	/**
	 * @brief Gets all peers.
	 *
	 * @return A vector of all peer nodes known.
	 */
	virtual std::vector<Node> get_peers() const;

	/**
	 * @brief Gets the neighbouring peers, i.e. children and the parent.
	 *
	 *        Will return an empty vector if the node is unknown.
	 *
	 * @param nodeID The ID of the node to fetch neighbouring peers for.
	 * @return A vector of child and parent nodes.
	 */
	virtual std::vector<Node> get_neighbour_peers(std::uint64_t nodeID) const;

	/**
	 * @brief Deletes a node from the list of peers.
	 *
	 * @param nodeID The ID of the node to delete.
	 * @return Deleted peer if it was deleted.
	 */
	virtual std::optional<Node> delete_peer(std::uint64_t nodeID);

	/**
	 * @brief Gets the certificate chain of the given node.
	 *
	 * @param nodeID The node to fetch a certificate chain for.
	 * @return A list of certificates, from the top-most CA, to the node's own
	 *         certificate. If a node cannot be found, no std::nullopt will be
	 *         returned instead.
	 */
	virtual std::optional<std::vector<X509_RAII>>
	get_certificate_chain(std::uint64_t nodeID);

protected:
	mutable std::mutex nodesMutex;
	std::map<std::uint64_t, Node> nodes;
	std::map<std::uint64_t, std::vector<std::uint64_t>> children;

	static bool validate_peer(const Node& peer);
};
