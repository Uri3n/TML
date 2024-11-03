# Tiny Multiprocessing Library
A tiny, cross-platform, single-header C++ 20 library that provides utilities for multiprocessing and interprocess communication. 

## Creating child processes
A process can be created with the `tml::Process` class. Specify the path (relative or absolute) of the executable to be ran in the constructor. You can start the process with `Process::launch()`. Once it's launched, it will run in the background and display it's output to the parent process' console by default. Additionally, you can call `Process::wait()` to block until it finishes execution. This method also returns a `tml::ExitCode`, which you can use to check if it ran successfully or not. Note that tml::Process will throw a `tml::TMLException` if it cannot be launched or if a problem occurs. This exception is derived from `std::exception`. 

```cpp
#include "tml.hpp"
#include <iostream>
using namespace tml;

int main() try {
  auto exit_code = Process("/bin/ls")
    .args({"-l", "-a"})  
    .working_directory("some/directory")
    .launch()
    .wait();

  if(exit_code.type != ExitCode::Type::Unknown) {
    std::cout << "The process exited with: " << exit_code.value << std::endl;
  }

  return 0;
} catch(const TMLException& e) {
  std::cerr << "TML Exception! what: " << e.what() << std::endl;
}
```

It's also possible to redirect a process' output stream into a buffer or file of your choosing,
query it's status to check if it's still running or not, recieve callbacks when the process exits, 
as well as forcibly terminate it. Also, note how in the following example the `nstr()` ("native string") macro is used.
This is a macro that converts a string literal to it's native representation. On Windows this will specify the string 
literal as being UTF-16 encoded, and on Mac and Linux it will be UTF-8, allowing for unicode characters in file and directory names.

```cpp
#include "tml.hpp"
#include <iostream>
using namespace tml;

int main() try {
  // A Windows example.
  Process first(nstr("powershell.exe"));
  Process second(nstr("ping"));
  Process third(nstr("ipconfig"));

  // Set first process' arguments.
  first.args({ nstr("ls"), nstr("-Hidden") });
  // Redirect output of the first process into a buffer.
  first.buffer_redirect(1024, [&](const std::vector<uint8_t>& buff) {
      // do something with the buffer idk...
  });


  // Set second process' arguments.
  second.args({nstr("google.com")});
  // Redirect the output into a file.
  second.file_redirect(nstr("output.txt"));


  // For the third process, let's set up a callback
  // so we don't have to check if it exited.
  third.on_exit([&](const ExitCode& code) {
    std::cout << "the third process exited!\n";
    std::cout << "exit code: " << code.value << '\n';
  });

    
  // Launch all three of the processes.
  first.launch();
  second.launch();
  third.launch();

    
  // check if the first process has exited.
  if(first.exited()) {
    std::cout << "The first process exited.\n";
  }

  // a different method. This also works.
  if(second.get_exit_code().type != ExitCode::Type::NotExited) {
    std::cout << "The second process exited.\n";
  }

  first.wait();
  second.wait();
  third.wait();
} catch(const TMLException& e) {
  std::cerr << "TML Exception! what: " << e.what() << std::endl;
}
```

## This documentation is not done, imma finish later

## Building
It's just a single header. Download tml.hpp from this repository and `#include` it into your project.
Note that you'll need to compile for the C++ 20 standard or later.
