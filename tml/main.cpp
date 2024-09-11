#include "tml.hpp"


class idk : public std::string {
public:
};

int main() {

    tml::Process myproc("dir");

    try {
        myproc
          .args({"/a"})
          .file_redirect("my_output.txt", true)
          .working_directory("C:\\Users\\diago")
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
