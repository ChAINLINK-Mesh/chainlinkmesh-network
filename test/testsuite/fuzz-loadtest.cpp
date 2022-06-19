#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>

extern "C" {
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
}

const constexpr auto ITERATIONS = 100000;
const constexpr auto PACKET_SIZE = 1400;

int main(const int argc, const char* const argv[]) {
	if (argc != 3) {
		if (argc > 0) {
			std::cerr << "Usage: " << argv[0] << " <ADDRESS> <PORT>\n";
		}
		return 1;
	}

	const char* const address = argv[1];
	std::uint16_t port{};

	try {
		const auto tempPort = std::stoul(argv[2]);

		if (tempPort > std::numeric_limits<decltype(port)>::max()) {
			std::cerr << "Port specified is too large\n";
			return 1;
		}

		port = static_cast<decltype(port)>(tempPort);
	} catch (const std::invalid_argument& /* ignored */) {
		std::cerr << "Port specified was not a number\n";
		return 1;
	} catch (const std::out_of_range& /* ignored */) {
		std::cerr << "Port specified is too large\n";
		return 1;
	}

	sockaddr_in server_addr{};
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);

	if (inet_pton(AF_INET, address, &server_addr.sin_addr) != 1) {
		std::cerr << "Failed to set server address\n";
		return 2;
	}

	std::array<std::uint8_t, PACKET_SIZE> random_bytes{};
	std::generate(random_bytes.begin(), random_bytes.end(), rand);
	std::array<std::uint8_t, 4096> recv_buffer{};
	std::uint64_t responseSize{};
	std::uint64_t iterationsSent{ ITERATIONS };

	const auto startTime = std::chrono::high_resolution_clock::now();

	for (std::uint32_t i = 0; i < ITERATIONS; i++) {
		const auto conn = socket(AF_INET, SOCK_STREAM, 0);

		if (conn == -1) {
			std::cerr << "Failed to create socket to server\n";
			return 3;
		}

		if (connect(conn, reinterpret_cast<const sockaddr*>(&server_addr),
		            sizeof(server_addr)) == -1) {
			iterationsSent--;
			close(conn);
			continue;
		}

		write(conn, random_bytes.data(), random_bytes.size());

		// Server responded to bogus request
		responseSize += read(conn, recv_buffer.data(), recv_buffer.size());

		close(conn);
	}

	const auto endTime = std::chrono::high_resolution_clock::now();
	const auto duration =
	    std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime)
	        .count();

	std::cout << "Sent " << iterationsSent << " packets in "
	          << (duration / 1000.0) << " seconds\n";

	if (responseSize != 0) {
		std::cerr << "Server responded to bogus requests. On average "
		          << (static_cast<double>(responseSize) /
		              static_cast<double>(iterationsSent))
		          << " bytes per request.\n";
	}

	if (iterationsSent != ITERATIONS) {
		std::cerr << "Failed to connect to server: "
		          << (ITERATIONS - iterationsSent) << " times\n";
		return 4;
	}

	return responseSize == 0 ? 0 : 255;
}
