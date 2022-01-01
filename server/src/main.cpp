#include "server.hpp"
#include <thread>

int main() {
	Server server{};
	server.start();
	while (std::cin.ignore()) {
		std::this_thread::sleep_for(std::chrono::seconds{ 1 });
	}
}