#include "tml.hpp"

int main() {
    errno = EINVAL;
    std::cout << tml::last_system_error() << std::endl;
    return 0;
}
