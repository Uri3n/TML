# Tiny Multiprocessing Library
A tiny, cross-platform, single-header C++ 20 library that provides utilities for multiprocessing and interprocess communication. 

## Creating child processes
A process can be created with the `tml::Process` class. Specify the path (relative or absolute) of the executable to be ran in the constructor. You can start the process with `Process::launch()`. Once it's launched, it will run in the background and display it's output to the parent process' console by default. Additionally, you can call `Process::wait()` to block until it finishes execution. This method also returns a `tml::ExitCode`, which you can use to check if it ran successfully or not. Note that tml::Process will throw a `tml::TMLException` if it cannot be launched or if a problem occurs. This exception is derived from `std::exception`. 

```cpp
#include "tml.hpp"
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
  return 0;
} catch(const TMLException& e) {
  std::cerr << "TML Exception! what: " << e.what() << std::endl;
}
```

## Lockable IPC Mechanisms
TML provides two lockable types, `tml::NamedMutex` and `tml::NamedSemaphore`. These are both similar to `std::mutex`
and `std::semaphore`, with the main difference being that these are openable and lockable **across processes**. 
Additionally, you can use `tml::LockGuard` as an RAII mechanism to automatically unlock these lockable types once they
leave scope (similar to `std::lock_guard`). These types are created with their respective `create()` and `create_or_open()` functions, and can be "opened" by other processes by calling `open()`. 

both `lock()` and `try_lock()` return an enum that specifies whether the lock was acquired or not, and whether
the process was blocked from acquiring the lock because there aren't any slots left to acquire.

The process that creates the semaphore or mutex will need to call `destroy()` on it. Any other process that opens
a reference to it needs to call `close()` instead. This is demonstrated in the code below.

```cpp
// 2 as the template parameter specifies
// that there are 2 semaphore slots.
auto sem = NamedSemaphore<2>::create_or_open(nstr("My_Semaphore"));
if(!sem.is_valid()) {
  std::cerr << "couldn't create the mutex.\n";
  return 1;
}

// Try to get a semaphore slot without blocking the thread.
const auto lock_res = sem.try_lock();
if(lock_res == Lock::Result::Blocked) {
  std::cout << "There isn't a semaphore slot we can use right now.";
} else if(lock_res == Lock::Result::Acquired) {
  std::cout << "We have the lock!\n";
  sem.unlock(); // relinquish our slot.
} else {
  // Something went wrong.
  std::cerr << last_system_error() << '\n';
}

// Call destroy() to clean up.
sem.destroy();
```

In the other process:
```cpp
// If a semaphore with this name doesn't exist,
// this call will fail. We should check for that.
auto sem = NamedSemaphore<2>::open(nstr("My_Semaphore"));
if(!sem.is_valid()) {
  std::cerr << "a semaphore with this name doesn't exist!\n";
  return 1;
}

// Set up a LockGuard so this gets unlocked for us automatically.
// (remember this also works for tml::NamedMutex)
LockGuard lock(sem);

// Close the semaphore handle.
sem.close();
```

## Named Pipes 
a `tml::NamedPipe` is an IPC mechanism used for sending messages between processes.
It follows the `create()` and `open()` idiom, much like the other IPC types in this library.
It's bidirectional by default, and a callback can be set up for receiving messages through the pipe.
```cpp
auto pipe = NamedPipe::create(nstr("My_NamedPipe"));
if(!pipe.is_open()) {
  std::cerr << "couldn't create the pipe.\n";
  return 1;
}

// Receiving messages with a callback:
pipe.on_receive([&](const AlignedFlatBuffer& buff) {
  // ... do something with the message.
});

// Receiving messages synchronously:
NativeString msg;
while(true) {
  const auto &[success, amount_read] = pipe.receive(msg);
  if(!success || amount_read == 0) {
    break;
  }

  if(msg == nstr("exit")) {
    std::cout << "I've been told to exit.\n";
    pipe.destroy();
    return 1;
  }
}

// destroy the pipe.
pipe.destroy();
```

## Shared Memory
a `tml::SharedRegion` is a flat, anonymous region of virtual memory that can be
shared across processes.
```cpp
// Create a shared memory region with a size of 1024 bytes.
auto shared = SharedRegion::create_or_open(nstr("My_SharedRegion"), 1024);
if(!shared.is_open()) {
  std::cerr << last_system_error() << std::endl;
  return 1;
}

// Copy a message into the shared region. 
char message[20] = "hello SharedRegion!";
memcpy(shared.get<>(), message, sizeof(message));

// Destroy the buffer.
shared.destroy();
```
If we wanted to open this region in a different process we'd do this:
```cpp
// Open the shared region that was created by
// the other process. Note that we don't need to specify the
// length here since we're opening an existing region.
auto shared = SharedRegion::open(nstr("My_SharedRegion"));
if(!shared.is_open()) {
  std::cerr << "A SharedRegion with that name doesn't exist!\n";
  return 1;
}

// Close the handle once we're done using it.
shared.close();
```

## Utility functions, and this_process
The library has several utility functions that you might find useful including:
- `tml::last_system_error()` - gets the last system-level error that occured as a string.
- `tml::spawn()` - creates a process in a detached state (runs in the background). This process
  does not need to be managed or cleaned up.
- `tml::this_process::kill()` - forcibly terminates the current process, not allowing for any resource cleanup.
- `tml::this_process::get_id()` - retrieves the process ID (PID) of the current process
- `tml::this_process::get()` - retrieves a handle to the current process.

there are a few others, but these ones are the most useful.

## Building
It's just a single header. Download tml.hpp from this repository and `#include` it into your project.
Note that you'll need to compile for the C++ 20 standard or later.
