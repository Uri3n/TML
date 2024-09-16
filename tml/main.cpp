#include "tml.hpp"

using namespace tml;
int main() {

    try {
        tml::spawn(ns("ls"), { ns("-l"), ns("--color=always") }, ns("/Users/Diago/Desktop"));
    }
    catch(const TMLException& e) {
        std::cerr << "exception: " << e.what() << '\n';
        return 1;
    }

    sleep(3);
    return 0;
}
