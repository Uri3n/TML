#include "tml.hpp"

int foo();

using namespace tml;
int main() {

    auto pipe = NamedPipe::create(ns("MyPipe"));
    if(!pipe.is_open()) {
        std::cerr << "failed to open pipe: " << last_system_error() << std::endl;
        return 1;
    }

    std::cout << "Beginning read...\n";
    pipe.on_receive([](const std::vector<uint8_t>& buffer) {
        std::cout << "Received message from the pipe:\n";
        std::cout.write((const char*)buffer.data(), buffer.size());
        std::cout.flush();
    });

    sleep(2);
    std::cout << "calling destroy\n";
    pipe.destroy();
    return 0;
}
