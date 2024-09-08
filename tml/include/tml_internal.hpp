//
// Created by Diago on 2024-09-07.
// This header file contains definitions that are internal
// to the project, and should not be accessible to the user.
//

#ifndef TML_INTERNAL_HPP
#define TML_INTERNAL_HPP
#include <cstdlib>
#include <cassert>
#include <string>
#include <iostream>

namespace tml {
    [[noreturn]] void _panic_impl(const std::string& file, int line, std::string msg = "");
}

[[noreturn]] inline void
tml::_panic_impl(const std::string& file, const int line, std::string msg) {
    std::cerr << "PANIC :: " << msg << "\n";
    std::cerr << "In file \"" << file << "\" at line " << line << ".\n";
    exit(EXIT_FAILURE);
}

#define tml_unreachable tml::_panic_impl(__FILE__, __LINE__)
#define tml_panic(msg)  tml::_panic_impl(__FILE__, __LINE__, msg)
#define tml_assert(condition) \
    if(!(condition))  tml::_panic_impl(__FILE__, __LINE__, std::string("Assertion failed: " #condition))


#endif //TML_INTERNAL_HPP
