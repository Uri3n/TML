#include "tml.hpp"

int main() {
    tml::Process myproc("ls");

    try {
        myproc
          .args({"-l"})
          .file_redirect("my_output.txt", false)
          .working_directory("/Users/Diago/Desktop")
          .launch();
    } catch(const tml::TMLException& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }

    const auto res = myproc.wait();
    std::cout << "exit code: " << res.value << '\n';
    std::cout << "exit type: " << (int)res.type << '\n';

    return 0;
}
