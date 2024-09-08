
#ifndef TML_HPP
#define TML_HPP

#if defined(_WIN32)
#define TML_WINDOWS
#elif defined(__APPLE__) && defined(__MACH__)
#define TML_MACOS
#elif defined(__linux__)
#define TML_LINUX
#else
#error "Unknown operating system - TML cannot be used on this platform."
#endif

#if defined(TML_WINDOWS)
#include <Windows.h>
#else // POSIX
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#endif

#include <exception>
#include <functional>
#include <array>


namespace tml {
    class Process;
    class Group;
    class OutputDevice;
    class Handle;
    class TMLException;
    class DeferredAction;
    struct ExitCode;
    
    std::string last_system_error();
}


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::DeferredAction ~
// - A very basic RAII wrapper around an invocable object.
// - Calls the invocable object when the destructor is invoked.
// - Comes with two macros to make using the class cleaner.
//

#define tml_defer(action)               auto _ = tml::DeferredAction(action);
#define tml_defer_if(condition, action) auto _ = tml::DeferredAction(condition, action);

class tml::DeferredAction {
    std::function<void()> action_;
    bool condition_       = false;
    bool using_condition_ = false;
public:
    ~DeferredAction() { action_(); }

    explicit DeferredAction(const decltype(action_)& action)
        : action_(action) {}
    explicit DeferredAction(const bool condition, const decltype(action_)& action)
        : action_(action), condition_(condition), using_condition_(true) {}
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::Handle ~
// - represents a medium of interaction with a child process
// - provides methods to close handles and kill processes
//

class tml::Handle {
public:
#if defined(TML_WINDOWS)
    using Value = ::HANDLE;
#else
    using Value = ::pid_t;
#endif

    void close();
    void kill();
    ExitCode get_exit_code() noexcept;
    Value get();

    static bool is_invalid_handle_state(const Handle& handle);
    static bool is_invalid_handle_state(Value value);
    static Value get_invalid_handle_state();

    ~Handle();
    explicit Handle(const Value value) : value_(value) {}
private:
    Value value_;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::ExitCode ~
// - represents the exit code of a child process.
// - the actual code value is DWORD on windows and int on linux.
//

struct tml::ExitCode {
#if defined(TML_WINDOWS)
    using Value = ::DWORD;
#else
    using Value = int;
#endif

    enum class Type : uint8_t {
        NotExited,  // The process has not exited yet.
        Normal,     // The process called "exit()" or returned from it's entry point.
        FromSignal, // On POSIX systems, indicates the process was terminated by a signal.
        Unknown     // Unknown exit condition.
    };

    const Value value;
    const Type  type;

    ~ExitCode() = default;
    ExitCode(const Value value, const Type type)
        : value(value), type(type) {}
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::OutputDevice ~
// - represents an output stream that can be written to by processes.
// - can be a pipe, file, or some other resource that stdout can be redirected to.
//

class tml::OutputDevice {
public:
#if defined(TML_WINDOWS)
    using Value = ::HANDLE;
#else
    using Value = int;
#endif

    struct Pipe;
    enum class Type : uint8_t {
        None,    // Invalid
        File,    // Output device is a file on disk.
        PipeEnd, // Pipe, read or write end not specified.
    };

    template<size_t out_size = 1024>
    auto read() -> std::array<uint8_t, out_size>;

    template<size_t out_size = 1024>
    auto read_into(std::array<uint8_t, out_size>& out) -> void;

    static auto get_invalid_handle_state()                        -> Value;
    static auto is_invalid_handle_state(Value value)              -> bool;
    static auto create(Value val, Type type)                      -> OutputDevice;
    static auto create_file(const std::string& name, bool append) -> OutputDevice;
    static auto create_pipe()                                     -> Pipe;

    ~OutputDevice() = default;
    OutputDevice() : value_(get_invalid_handle_state()) {}
private:
    Value value_{};
    Type  type_ = Type::None;
};

struct tml::OutputDevice::Pipe {
    OutputDevice read_end;
    OutputDevice write_end;
    ~Pipe() = default;
    Pipe()  = default;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::TMLException (and friends) ~
// - represents a native operating system error.
// - thrown when certain serious errors occur, including:
// - process could not be started.
// - process could not be killed.
// - handle could not be closed.
//

class tml::TMLException final : public std::exception {
public:
    enum class Type : uint8_t {
        None,
        ProcessTerminationException,
        ProcessLaunchException,
        OutputDeviceReadException,
        OutputDeviceCreationException,
    };

    [[nodiscard]] auto what() const noexcept -> const char * override;
    [[nodiscard]] auto type() const noexcept -> Type;

    static auto ProcessTerminationException()   -> TMLException;
    static auto ProcessLaunchException()        -> TMLException;
    static auto OutputDeviceReadException()     -> TMLException;
    static auto OutputDeviceCreationException() -> TMLException;
    
    ~TMLException() override = default;
    TMLException(std::string what, const Type type)
        : what_(std::move(what)), type_(type) {}
private:
    const std::string what_;
    const Type type_;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::Process ~
// - class that represents a child process
// - provides methods for performing the following:
// - registering callbacks for important events (exit, write to stdout, etc)
// - terminating processes
// - set important things like working directories
//

class tml::Process {
public:
    Process(const Process&)            = delete;
    Process& operator=(const Process&) = delete;

    ~Process();
    explicit Process(const std::string& name)
        : handle_(Handle::get_invalid_handle_state()), name_(name) {}
private:
    Handle handle_;
    std::string name_;
    std::vector<std::string> arguments_;

};

#endif //TML_HPP
