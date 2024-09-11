
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
    #error "Supported platforms: Windows, MacOS, and Linux."
#endif

#if defined(__JETBRAINS_IDE__)
    #define TML_VALUE_PARAM [[jetbrains::pass_by_value]]
    #define TML_NEVER_USED  [[jetbrains::guard]]
#else
    #define TML_VALUE_PARAM
    #define TML_NEVER_USED
#endif

#if defined(TML_WINDOWS)
    #include <Windows.h>
#else // POSIX
    #include <unistd.h>
    #include <csignal>
    #include <sys/wait.h>
    #include <sys/types.h>
    #include <sys/mman.h>
    #include <fcntl.h>
#endif

#if defined(__clang__) || defined(__GNUC__)
    #if defined(__clang__)
        #define TML_COMPILEDWITH_CLANG
    #else
        #define TML_COMPILEDWITH_GCC
    #endif
    #if defined(__JETBRAINS_IDE__)
        #define TML_ATTR_NOINLINE    inline __attribute__((noinline))
        #define TML_ATTR_FORCEINLINE inline __attribute__((always_inline))
    #else
        #define TML_ATTR_NOINLINE    __attribute__((noinline))
        #define TML_ATTR_FORCEINLINE __attribute__((always_inline))
    #endif

#elif defined(_MSC_VER_)
    #define TML_COMPILEDWITH_MSVC
    #define TML_ATTR_NOINLINE    __declspec(noinline)
    #define TML_ATTR_FORCEINLINE __forceinline
#else
    #define TML_COMPILEDWITH_UNKNOWN
    #define TML_ATTR_NOINLINE
    #define TML_ATTR_FORCEINLINE
#endif

#include <iostream>
#include <exception>
#include <filesystem>
#include <thread>
#include <functional>
#include <utility>
#include <variant>
#include <array>
#include <chrono>


namespace tml {
    class Process;
    class Group;
    class OutputDevice;
    class Handle;
    class TMLException;
    class DeferredAction;
    struct ExitCode;

    template<size_t len>
    using FlatBuffer = std::array<uint8_t, len>;
    class AlignedFlatBuffer;

    std::string last_system_error();
    [[noreturn]] void _panic_impl(const std::string& file, int line, const std::string& msg = "");
}

namespace tml::this_process {
    Handle get();
    size_t get_id();
    [[noreturn]] void kill(int status = 0);
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

    explicit DeferredAction(decltype(action_)  action)
        : action_(std::move(action)) {}
    explicit DeferredAction(const bool condition, decltype(action_)  action)
        : action_(std::move(action)),
        condition_(condition),
        using_condition_(true) {}
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::AlignedFlatBuffer ~
// - represents a page aligned, non-reallocatable block of virtual memory.
// - Stores a pointer and a size.
// - Used to read from pipes without using std::vector.
// - Preferred over tml::FlatBuffer when the size of the allocation cannot be known at compile time.
//

class tml::AlignedFlatBuffer {
public:
    void  destroy() noexcept;
    [[nodiscard]] void*  data() const;
    [[nodiscard]] size_t size() const;

    AlignedFlatBuffer(const AlignedFlatBuffer&)            = delete;
    AlignedFlatBuffer& operator=(const AlignedFlatBuffer&) = delete;
    AlignedFlatBuffer(AlignedFlatBuffer&& other)            noexcept;
    AlignedFlatBuffer& operator=(AlignedFlatBuffer&& other) noexcept;

    ~AlignedFlatBuffer();
    explicit AlignedFlatBuffer(size_t non_aligned_size);
private:
    void*  buffer_ = nullptr;
    size_t size_   = 0;
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
    void invalidate();
    void kill()  const;
    [[nodiscard]] ExitCode get_exit_code()  const noexcept;
    [[nodiscard]] Value get() const noexcept;

    static bool is_invalid_handle_state(const Handle& handle);
    static bool is_invalid_handle_state(Value value);
    static Value get_invalid_handle_state();

    ~Handle() = default;
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

    Value value;
    Type  type;

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
    FlatBuffer<out_size> read();

    template<size_t out_size = 1024>
    void read_into(FlatBuffer<out_size>& out);
    void close();
    [[nodiscard]] Value value() const;

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

#define TML_EXCEPTION_TYPE_LIST          \
    TML_X(None)                          \
    TML_X(ProcessTerminationException)   \
    TML_X(ProcessLaunchException)        \
    TML_X(OutputDeviceReadException)     \
    TML_X(OutputDeviceCreationException) \
    TML_X(OutputDeviceCloseException)    \
    TML_X(FileSystemException)           \
    TML_X(SystemMemoryException)         \


class tml::TMLException final : public std::exception {
public:
#define TML_X(NAME) NAME,
    enum class Type : uint8_t {
        TML_EXCEPTION_TYPE_LIST
    };
#undef TML_X

    [[nodiscard]] auto what() const noexcept -> const char * override;
    [[nodiscard]] auto type() const noexcept -> Type;

#define TML_X(NAME) static ::tml::TMLException NAME();
    TML_EXCEPTION_TYPE_LIST
#undef TML_X
    
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
    using AlignedBufferOutputCallback = std::function<void(const AlignedFlatBuffer&)>;
    using DynamicBufferOutputCallback = std::function<void(const std::vector<uint8_t>&)>;
    using OnExitCallback              = std::function<void(const ExitCode&)>;

    ///////////////////////////////////////////////////////////////////////////////////////
    // Public methods

    Process(const Process&)            = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&&) noexcept;
    Process& operator=(Process&&) noexcept;

    Process& args(const std::vector<std::string>& arg_list);
    Process& args(std::vector<std::string>&& arg_list);
    Process& working_directory(const std::string& dir);
    Process& file_redirect(const std::string& file_name, bool append_contents);
    Process& on_exit(OnExitCallback callback);
    Process& launch();

    [[nodiscard]] ExitCode get_exit_code();
    [[nodiscard]] bool exited();

    template<typename Callback> requires
        std::constructible_from<AlignedBufferOutputCallback, Callback> ||
        std::constructible_from<DynamicBufferOutputCallback, Callback>
    Process& buffer_redirect(size_t buff_size, Callback callback);

    ExitCode wait();
    void wait_for(std::chrono::milliseconds time_ms);

    ///////////////////////////////////////////////////////////////////////////////////////
    // non-move constructor, destructor

    ~Process();
    explicit Process(std::string name)
    : handle_(Handle::get_invalid_handle_state()),
      name_(std::move(name)),
      callback_buffer_hint_(0),
#if defined(TML_MACOS) || defined(TML_LINUX)
      posix_cached_exit_code_(-1, ExitCode::Type::Unknown),
#endif
      output_(std::monostate()),
      output_callback_(std::monostate()),
      exit_callback_(std::monostate()){}

    ///////////////////////////////////////////////////////////////////////////////////////
    // Things we need to do post-launch

private:
#if defined(TML_MACOS) || defined(TML_LINUX)
    [[noreturn]] void _posix_child_launch_impl();
    void _posix_parent_launch_impl();
    static ExitCode _posix_blocking_wait_impl(Handle child_handle);
#endif

    static void _launch_pipe_aligned_read_impl(OutputDevice::Value, AlignedBufferOutputCallback, size_t);
    static void _launch_pipe_dyn_read_impl(OutputDevice::Value, DynamicBufferOutputCallback, size_t);
    static void _launch_exit_wait_impl(Handle child_handle, OnExitCallback cb);

    ///////////////////////////////////////////////////////////////////////////////////////
    // Private members

    Handle handle_;
    std::string name_;
    std::string working_directory_;
    std::vector<std::string> arguments_;
    size_t callback_buffer_hint_;

#if defined(TML_MACOS) || defined(TML_LINUX)
    ExitCode posix_cached_exit_code_;
#endif

    std::unique_ptr<std::thread> output_callback_worker_ = nullptr;
    std::unique_ptr<std::thread> exit_callback_worker_   = nullptr;

    std::variant<
        OutputDevice::Pipe,
        OutputDevice,
        std::monostate
    > output_;

    std::variant<
        AlignedBufferOutputCallback,
        DynamicBufferOutputCallback,
        std::monostate
    > output_callback_;

    std::variant<
        OnExitCallback,
        std::monostate
    > exit_callback_;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin utility functions. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

[[noreturn]] inline void
tml::_panic_impl(const std::string& file, const int line, const std::string& msg) {
    std::cerr << "PANIC :: " << msg << "\n";
    std::cerr << "In file \"" << file << "\" at line " << line << ".\n";
    exit(EXIT_FAILURE);
}

#define tml_unreachable tml::_panic_impl(__FILE__, __LINE__)
#define tml_panic(msg)  tml::_panic_impl(__FILE__, __LINE__, msg)
#define tml_assert(condition) \
    if(!(condition))  tml::_panic_impl(__FILE__, __LINE__, std::string("Assertion failed: " #condition))

#if defined(TML_WINDOWS)

[[noreturn]] TML_ATTR_FORCEINLINE void
tml::this_process::kill(const int status) {
    ExitProcess((UINT)status);
}

TML_ATTR_FORCEINLINE size_t
tml::this_process::get_id() {
    return static_cast<size_t>(GetCurrentProcessId());
}

TML_ATTR_FORCEINLINE tml::Handle
tml::this_process::get() {
    return Handle(GetCurrentProcess());
}

std::string
last_system_error() {
    DWORD err_code = GetLastError();
    DWORD result   = 0;
    LPSTR outbuf   = nullptr;

    if(err_code == ERROR_SUCCESS) {
        return "";
    }

    // Documentation: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagea
    result = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER              // Specifies that a buffer should be allocated for the message.
            | FORMAT_MESSAGE_FROM_SYSTEM            // Indicates that the system message table should be searched.
            | FORMAT_MESSAGE_IGNORE_INSERTS,        // Indicates that insert sequences (i.e. "%1") should be ignored.
        nullptr,                                    // Optional, pointer to the message definition
        err_code,                                   // The error code to be formatted.
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),  // Default language
        reinterpret_cast<LPSTR>(&outbuf),           // Function will allocate buffer at this address.
        0,                                          // Specifies size of the output buffer. Not needed in this case.
        nullptr                                     // Optional va_list for insert sequences.
    );

    if(result == 0) { // failure
        return "";
    }

    std::string out(outbuf);
    LocalFree(outbuf);
    return out;
}

#else // OS == POSIX

[[noreturn]] TML_ATTR_FORCEINLINE void
tml::this_process::kill(const int status) {
    _exit(status); // NOT the same as C's exit()
}

TML_ATTR_FORCEINLINE size_t
tml::this_process::get_id() {
    return static_cast<size_t>(getpid());
}

TML_ATTR_FORCEINLINE tml::Handle
tml::this_process::get() {
    return Handle(getpid());
}

inline std::string
tml::last_system_error() {
    char buffer[256]   = { 0 };
    const int err_code = errno;

    if(err_code == 0) {
        return "";
    }

    if(strerror_r(err_code, buffer, sizeof(buffer)) == 0) {
        std::string out(buffer);
        return out;
    }

    return "";
}
#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::TMLException methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

inline tml::TMLException::Type
tml::TMLException::type() const noexcept {
    return type_;
}

inline const char*
tml::TMLException::what() const noexcept {
    return what_.c_str();
}

#define TML_X(NAME)                              \
inline tml::TMLException                         \
tml::TMLException::NAME() {                      \
    return { #NAME ": " + last_system_error(),   \
        Type::NAME };                            \
}                                                \

TML_EXCEPTION_TYPE_LIST
#undef TML_X


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::Handle methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////


TML_ATTR_FORCEINLINE bool
tml::Handle::is_invalid_handle_state(const Value value) {
    return value == get_invalid_handle_state();
}

TML_ATTR_FORCEINLINE void
tml::Handle::invalidate() {
    value_ = get_invalid_handle_state();
}

TML_ATTR_FORCEINLINE bool
tml::Handle::is_invalid_handle_state(const Handle &handle) {
    return is_invalid_handle_state(handle.value_);
}

[[nodiscard]] TML_ATTR_FORCEINLINE tml::Handle::Value
tml::Handle::get() const noexcept {
    return value_;
}

#if defined(TML_WINDOWS)

tml::Handle::Value
tml::Handle::get_invalid_handle_state() {
    return nullptr;
}

void
tml::Handle::kill() {
    if(!::TerminateProcess(value_, 0)) {
        throw TMLException::ProcessTerminationException();
    }
}

void
tml::Handle::close() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    if(!CloseHandle(value_)) {
        throw TMLException::ProcessTerminationException();
    }

    value_ = get_invalid_handle_state();
}

[[nodiscard]] inline tml::ExitCode
tml::Handle::get_exit_code() const noexcept {
    DWORD exit_code = 0;
    if(!GetExitCodeProcess(value_, &exitcode)) {
        throw TMLException(last_system_error(), TMLException::Type::None);
    }
    if(exit_code == STILL_ACTIVE) {
        return { exit_code, ExitCode::Type::NotExited };
    }

    return { exit_code, ExitCode::Type::Normal };
}

#else // OS == POSIX

inline tml::Handle::Value
tml::Handle::get_invalid_handle_state() {
    return -1;
}

inline void
tml::Handle::kill() const {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    if(::kill(value_, SIGTERM) == -1) {
        throw TMLException::ProcessTerminationException();
    }
}

[[nodiscard]] inline tml::ExitCode
tml::Handle::get_exit_code() const noexcept {
    int status         = 0;
    const pid_t result = ::waitpid(value_, &status, WNOHANG);

    if(result < 0) {
        return { -1, ExitCode::Type::Unknown };  // an error has occurred.
    }
    if(result == 0) {
        return { 0, ExitCode::Type::NotExited }; // The process is still running.
    }

    if(result == value_) {
        if(WIFEXITED(status)) {
            return { WEXITSTATUS(status), ExitCode::Type::Normal };
        }
        if(WIFSIGNALED(status)) {
            return { WTERMSIG(status), ExitCode::Type::FromSignal };
        }
        if(WIFSTOPPED(status)) {
            return { WSTOPSIG(status), ExitCode::Type::FromSignal };
        }
        return { -1, ExitCode::Type::Unknown };
    }

    tml_unreachable;
}

inline void
tml::Handle::close() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    kill(); // no notion of "closing" a process on posix systems.
    value_ = get_invalid_handle_state();
}

#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::OutputDevice methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

inline tml::OutputDevice
tml::OutputDevice::create(const Value val, const Type type) {
    OutputDevice device;
    device.value_ = val;
    device.type_  = type;
    return device;
}

[[nodiscard]] inline tml::OutputDevice::Value
tml::OutputDevice::value() const {
    return value_;
}


#if defined(TML_WINDOWS)
tml::OutputDevice::Value
tml::OutputDevice::get_invalid_handle_state() {
    return nullptr;
}

inline void
tml::OutputDevice::close() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    if(!CloseHandle(value_)) {
        throw TMLException(last_system_error(), TMLException::Type::None);
    }

    value_ = get_invalid_handle_state();
}

bool
tml::OutputDevice::is_invalid_handle_state(const Value value) {
    return value == nullptr || value == INVALID_HANDLE_VALUE;
}

tml::OutputDevice
tml::OutputDevice::create_file(const std::string& name, const bool append) {
    OutputDevice device;
    DWORD flags = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    if(append) {
        flags |= FILE_APPEND_DATA;
    }

    // Documentation: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
    device.type_  = Type::File
    device.value_ = CreateFileA(
        name.c_str(),                        // Name of the file.
        flags,                               // Access flags.
        FILE_SHARE_READ | FILE_SHARE_WRITE,  // File share mode. Mostly irrelevant.
        nullptr,                             // Security attributes for a descriptor. Optional.
        OPEN_ALWAYS,                         // Open mode.
        FILE_ATTRIBUTE_NORMAL,               // File attributes. File is normal.
        nullptr                              // Optional handle to a template file.
    );

    if(device.value_ == INVALID_HANDLE_VALUE) {
        throw TMLException::OutputDeviceCreationException();
    }

    // Opening a file in append mode on Windows does not move
    // the file pointer to the end of the file. We need to do it here if need be.
    if(append) {
        SetFilePointer(device.value_, 0, nullptr, FILE_END);
    }

    return device;
}

tml::OutputDevice::Pipe
tml::OutputDevice::create_pipe() {
    Pipe pipe;
    pipe.read_end.type_   = Type::PipeEnd;
    pipe.write_end.type_  = Type::PipeEnd;

    if(!CreatePipe(&pipe.read_end.value_, &pipe.write_end.value_, nullptr, 0)) {
        throw TMLException::OutputDeviceCreationException();
    }
    return pipe;
}

#else // OS == POSIX

inline void
tml::OutputDevice::close() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    if(::close(value_) == -1) {
        throw TMLException(last_system_error(), TMLException::Type::None);
    }

    value_ = get_invalid_handle_state();
}

inline tml::OutputDevice::Value
tml::OutputDevice::get_invalid_handle_state() {
    return -1;
}

inline bool
tml::OutputDevice::is_invalid_handle_state(const Value value) {
    return value == get_invalid_handle_state();
}

inline tml::OutputDevice
tml::OutputDevice::create_file(const std::string& name, const bool append) {
    OutputDevice device;
    int flags = O_RDWR | O_CREAT;
    if(append) {
        flags |= O_APPEND;
    }

    device.type_  = Type::File;
    device.value_ = ::open(name.c_str(), flags, 0644);
    if(device.value_ == -1) {
        throw TMLException::OutputDeviceCreationException();
    }

    return device;
}

inline tml::OutputDevice::Pipe
tml::OutputDevice::create_pipe() {
    int fd[2] = { 0 };
    if(pipe(fd) == -1) {
        throw TMLException::OutputDeviceCreationException();
    }

    Pipe pipe;
    pipe.read_end.value_  = fd[0];
    pipe.write_end.value_ = fd[1];
    pipe.read_end.type_   = Type::PipeEnd;
    pipe.write_end.type_  = Type::PipeEnd;
    return pipe;
}

template<size_t out_size>
auto tml::OutputDevice::read() -> FlatBuffer<out_size> {
    std::array<uint8_t, out_size> out;
    std::fill(out.begin(), out.end(), '\0');
    if(::read(value_, out.data(), out.size()) == -1) {
        throw TMLException::OutputDeviceReadException();
    }

    return out;
}

template<size_t out_size>
auto tml::OutputDevice::read_into(FlatBuffer<out_size>& out) -> void {
    if(::read(value_, out.data(), out.size()) == -1) {
        throw TMLException::OutputDeviceReadException();
    }
}

#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::AlignedFlatBuffer methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

inline
tml::AlignedFlatBuffer::~AlignedFlatBuffer() {
    destroy();
}

inline
tml::AlignedFlatBuffer::AlignedFlatBuffer(AlignedFlatBuffer&& other) noexcept {
    buffer_       = other.buffer_;
    size_         = other.size_;
    other.buffer_ = nullptr;
    other.size_   = 0;
}

inline tml::AlignedFlatBuffer&
tml::AlignedFlatBuffer::operator=(AlignedFlatBuffer&& other) noexcept {
    destroy();
    buffer_       = other.buffer_;
    size_         = other.size_;
    other.buffer_ = nullptr;
    other.size_   = 0;
    return *this;
}

[[nodiscard]] TML_ATTR_FORCEINLINE void*
tml::AlignedFlatBuffer::data() const {
    return buffer_;
}

[[nodiscard]] TML_ATTR_FORCEINLINE size_t
tml::AlignedFlatBuffer::size() const {
    return size_;
}

#if defined(TML_WINDOWS)

inline
tml::AlignedFlatBuffer::AlignedFlatBuffer (const size_t non_aligned_size) {
    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    buffer_ = VirtualAlloc(
        nullptr,                   // optional address to allocate at.
        non_aligned_size,          // size of memory before alignment.
        MEM_COMMIT | MEM_RESERVE,  // Virtual page states. reserve pages and commit them immediately.
        PAGE_READWRITE             // Page protection, read/write.
    );

    size_ = non_aligned_size;
    if(buffer_ == nullptr) {
        throw TMLException::SystemMemoryException();
    }
}

inline void
tml::AlignedFlatBuffer::destroy() noexcept {
    if(buffer_ == nullptr || size_ == 0) {
        return;
    }

    VirtualFree(buffer_, 0, MEM_RELEASE);
    buffer_ = nullptr;
    size_   = 0;
}

#else // OS == POSIX

inline
tml::AlignedFlatBuffer::AlignedFlatBuffer(const size_t non_aligned_size) {
    // https://pubs.opengroup.org/onlinepubs/9699919799.2018edition/functions/mmap.html
    buffer_ = mmap(
        nullptr,                      // optional allocation address.
        non_aligned_size,             // size before page alignment
        PROT_READ | PROT_WRITE,       // read/write memory protections
        MAP_PRIVATE | MAP_ANONYMOUS,  // MAP_ANONYMOUS = not backed by memory object
        -1,                           // fd for memory object. Optional because of MAP_ANONYMOUS
        0                             // file descriptor offset. Not needed here.
    );

    size_ = non_aligned_size;
    if(buffer_ == MAP_FAILED) {
        throw TMLException::SystemMemoryException();
    }
}

inline void
tml::AlignedFlatBuffer::destroy() noexcept {
    if(buffer_ == nullptr || size_ == 0) {
        return;
    }

    // Probably don't care if this fails.
    // Even if it does, the fuck are you supposed to do? lol.
    munmap(buffer_, size_);
    buffer_ = nullptr;
    size_   = 0;
}

#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::Process methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

inline tml::Process&
tml::Process::operator=(Process&& other) noexcept {
#if defined(TML_WINDOWS)
    handle_.kill();
    handle_.close();
#else
    handle_.close();
#endif

    if(exit_callback_worker_)   exit_callback_worker_->join();
    if(output_callback_worker_) output_callback_worker_->join();

    this->handle_                 = other.handle_;
    this->callback_buffer_hint_   = other.callback_buffer_hint_;
    this->output_                 = other.output_;
    this->exit_callback_worker_   = std::move(other.exit_callback_worker_);
    this->output_callback_worker_ = std::move(other.output_callback_worker_);
    this->name_                   = std::move(other.name_);
    this->working_directory_      = std::move(other.working_directory_);
    this->arguments_              = std::move(other.arguments_);
    this->exit_callback_          = std::move(other.exit_callback_);
    this->output_callback_        = std::move(other.output_callback_);

#if defined(TML_MACOS) || defined(TML_LINUX)
    this->posix_cached_exit_code_ = other.posix_cached_exit_code_;
#endif

    other.output_          = std::monostate();
    other.exit_callback_   = std::monostate();
    other.output_callback_ = std::monostate();
    other.handle_.invalidate();

    return *this;
}

inline
tml::Process::Process(Process&& other) noexcept
    : handle_(other.handle_),
     name_(std::move(other.name_)),
     working_directory_(std::move(other.working_directory_)),
     arguments_(std::move(other.arguments_)),
     callback_buffer_hint_(other.callback_buffer_hint_),
#if defined(TML_LINUX) || defined(TML_MACOS)
    posix_cached_exit_code_(other.posix_cached_exit_code_),
#endif
     output_callback_worker_(std::move(other.output_callback_worker_)),
     exit_callback_worker_(std::move(other.exit_callback_worker_)),
     output_(other.output_),
     output_callback_(std::move(other.output_callback_)),
     exit_callback_(std::move(other.exit_callback_))
{
    other.output_          = std::monostate();
    other.exit_callback_   = std::monostate();
    other.output_callback_ = std::monostate();
    other.handle_.invalidate();
}

TML_ATTR_FORCEINLINE tml::Process&
tml::Process::args(const std::vector<std::string>& arg_list) {
    arguments_ = arg_list;
    return *this;
}

TML_ATTR_FORCEINLINE tml::Process&
tml::Process::args(std::vector<std::string>&& arg_list) {
    arguments_ = arg_list;
    return *this;
}

[[nodiscard]] inline tml::ExitCode
tml::Process::get_exit_code() {
    if(posix_cached_exit_code_.type != ExitCode::Type::Unknown) {
        return posix_cached_exit_code_;
    }

    const auto code = handle_.get_exit_code();
    if(posix_cached_exit_code_.type == ExitCode::Type::Unknown
        && code.type != ExitCode::Type::NotExited
    ) {
        posix_cached_exit_code_ = code;
    }

    return code;
}

inline tml::Process&
tml::Process::working_directory(const std::string &dir) {
    namespace fs = std::filesystem;
    const std::string err_msg = "Specified working directory \"" + dir + "\" ";

    if(!fs::exists(dir)) {
        throw TMLException(err_msg + "does not exist.", TMLException::Type::FileSystemException);
    }
    if(!is_directory(fs::path(dir))) {
        throw TMLException(err_msg + "is not a directory.", TMLException::Type::FileSystemException);
    }

    working_directory_ = dir;
    return *this;
}

template<typename Callback> requires
    std::constructible_from<tml::Process::AlignedBufferOutputCallback, Callback> ||
    std::constructible_from<tml::Process::DynamicBufferOutputCallback, Callback>
auto tml::Process::buffer_redirect(const size_t buff_size, Callback callback) -> Process& {
    if(    !std::holds_alternative<std::monostate>(output_)
        || !std::holds_alternative<std::monostate>(output_callback_)) {
        return *this;
    }

    callback_buffer_hint_ = buff_size;
    output_callback_      = callback;
    output_               = OutputDevice::create_pipe();
    return *this;
}

TML_ATTR_FORCEINLINE tml::Process&
tml::Process::file_redirect(const std::string& file_name, const bool append_contents) {
    if(    !std::holds_alternative<std::monostate>(output_)
        || !std::holds_alternative<std::monostate>(output_callback_)) {
        return *this;
    }

    output_ = OutputDevice::create_file(file_name, append_contents);
    return *this;
}

TML_ATTR_FORCEINLINE tml::Process&
tml::Process::on_exit(OnExitCallback callback) {
    if(!std::holds_alternative<std::monostate>(exit_callback_)) {
        return *this;
    }

    exit_callback_ = callback;
    return *this;
}


#if defined(TML_WINDOWS)
// TODO: launch, exit wait and output impl

inline
tml::Process::~Process() {
    if(Handle::is_invalid_handle_state(handle_)
        || handle_.get_exit_code().type != ExitCode::Type::NotExited) {
        return;
    }
    handle_.kill();
    handle_.close();
}

#else // OS == POSIX

[[noreturn]] inline void
tml::Process::_posix_child_launch_impl() {
    auto* pipe_ptr    = std::get_if<OutputDevice::Pipe>(&output_);
    auto* file_ptr    = std::get_if<OutputDevice>(&output_);
    auto  hredirect   = OutputDevice::get_invalid_handle_state();
    std::vector argv  = { const_cast<char*>(name_.c_str()) };

    if(pipe_ptr != nullptr) {                         // If we need to redirect output into a pipe:
        pipe_ptr->read_end.close();                   // Close the read end of the pipe.
        hredirect = pipe_ptr->write_end.value();      // Redirect output to the write end of the pipe.
    } else if(file_ptr != nullptr) {
        hredirect = file_ptr->value();
    }

    if(!OutputDevice::is_invalid_handle_state(hredirect)) {
        const int dup_stdout = dup2(hredirect, STDOUT_FILENO);  // call dup2() to redirect stdout
        const int dup_stderr = dup2(hredirect, STDERR_FILENO);  // call dup2() to redirect stderr
        if(dup_stdout == -1 || dup_stderr == -1) {              // if either of these fail just exit().
            exit(420);
        }
    }

    for(const auto& arg : arguments_) {
        if(arg.empty()) continue;
        argv.emplace_back(const_cast<char*>(arg.c_str()));
    }

    argv.emplace_back(nullptr);                       // POSIX argv array must end in a null pointer.
    if(!working_directory_.empty()) {                 // Set working directory of the child.
        chdir(working_directory_.c_str());            // Not worth error checking this frankly.
    }

    execvp(name_.c_str(), argv.data());               // Replace child process' image.
    exit(420);                                        // This call is uncreachable if execvp succeeds.
}

inline void
tml::Process::_posix_parent_launch_impl() {
    auto*       ppipe       = std::get_if<OutputDevice::Pipe>(&output_);
    const auto* pdyncb      = std::get_if<DynamicBufferOutputCallback>(&output_callback_);
    const auto* palignedcb  = std::get_if<AlignedBufferOutputCallback>(&output_callback_);
    const auto* pexitcb     = std::get_if<OnExitCallback>(&exit_callback_);

    //
    // If there's an exit callback, set up a worker thread.
    //

    if(pexitcb != nullptr) {
        exit_callback_worker_ = std::make_unique<std::thread>(
            _launch_exit_wait_impl,
            handle_,
            *pexitcb
        );
    }

    if(ppipe == nullptr) {
        return;
    }

    //
    // If there is a pipe, set up callbacks for it.
    // Also make sure to close the write end of the pipe.
    //

    ppipe->write_end.close();
    if(pdyncb != nullptr) {
        output_callback_worker_ = std::make_unique<std::thread> (
            _launch_pipe_dyn_read_impl,
            ppipe->read_end.value(),
            *pdyncb,
            callback_buffer_hint_
        );
    }

    else if(palignedcb != nullptr) {
        output_callback_worker_ = std::make_unique<std::thread>(
            _launch_pipe_aligned_read_impl,
            ppipe->read_end.value(),
            *palignedcb,
            callback_buffer_hint_
        );
    }

    else {
        tml_panic("Launched process has a pipe, but no output callback.");
    }
}

inline tml::ExitCode
tml::Process::_posix_blocking_wait_impl(TML_VALUE_PARAM const Handle child_handle) {
    int status = 0;
    const auto pid = ::waitpid(child_handle.get(), &status, 0);

    // Once waiting is complete get the exit code.
    if(pid < 0) {
        return {-1, ExitCode::Type::Unknown};
    }
    if(pid == 0) {
        return {0, ExitCode::Type::NotExited};
    }

    if(pid == child_handle.get()) {
        if(WIFEXITED(status)) {
            return {WEXITSTATUS(status), ExitCode::Type::Normal};
        }
        if(WIFSIGNALED(status)) {
            return {WTERMSIG(status), ExitCode::Type::FromSignal};
        }
        if(WIFSTOPPED(status)) {
            return {WSTOPSIG(status), ExitCode::Type::FromSignal};
        }
        return {-1, ExitCode::Type::Unknown };
    }

    tml_unreachable;
}

inline void
tml::Process::_launch_exit_wait_impl(
    TML_VALUE_PARAM const Handle child_handle,
    TML_VALUE_PARAM OnExitCallback cb
) {
    const auto code = _posix_blocking_wait_impl(child_handle);
    cb(code);
}

inline void
tml::Process::_launch_pipe_aligned_read_impl(
    TML_VALUE_PARAM const OutputDevice::Value pipe_end,
    TML_VALUE_PARAM AlignedBufferOutputCallback cb,
    size_t buffer_length
) {
    if(buffer_length == 0) {
        buffer_length = 200;
    }

    const AlignedFlatBuffer buffer(buffer_length);
    while(::read(pipe_end, buffer.data(), buffer.size()) > 0) {
        cb(buffer);
    }
}

inline void
tml::Process::_launch_pipe_dyn_read_impl(
    TML_VALUE_PARAM const OutputDevice::Value pipe_end,
    TML_VALUE_PARAM DynamicBufferOutputCallback cb,
    size_t buffer_length
) {
    if(buffer_length == 0) {
        buffer_length = 200;
    }

    std::vector<uint8_t> buffer(buffer_length);
    while(::read(pipe_end, buffer.data(), buffer.size())) {
        cb(buffer);
    }
}

inline bool
tml::Process::exited() {
    if(posix_cached_exit_code_.type != ExitCode::Type::Unknown) {
        return true;
    }

    const auto code = handle_.get_exit_code();
    if(posix_cached_exit_code_.type == ExitCode::Type::Unknown
        && code.type != ExitCode::Type::NotExited
    ) {
        posix_cached_exit_code_ = code;
    }

    return code.type != ExitCode::Type::NotExited;
}

inline tml::ExitCode
tml::Process::wait() {
    if(posix_cached_exit_code_.type == ExitCode::Type::Unknown) {
        posix_cached_exit_code_ = _posix_blocking_wait_impl(handle_);
    }
    return posix_cached_exit_code_;
}

inline tml::Process&
tml::Process::launch() {
    const auto pid = fork();                          // Call fork() to spawn a child.
    if(pid < 0) {                                     // < 0 indicates failure.
        throw TMLException::ProcessLaunchException();
    }
    if(pid == 0) {                                    // We're inside the child (that sounds so wrong but idk).
        _posix_child_launch_impl();                   // Redirect stdout, call chdir, etc.
    }

    handle_ = Handle(pid);
    _posix_parent_launch_impl();                      // Set up callback threads.
    return *this;                                     // Return class instance
}

inline
tml::Process::~Process() {
    tml_defer([this] {
        if(output_callback_worker_) output_callback_worker_->join();
        if(exit_callback_worker_)   exit_callback_worker_->join();
    });

    // ReSharper disable once CppTooWideScopeInitStatement
    const auto child_exit = handle_.get_exit_code().type;
    if(Handle::is_invalid_handle_state(handle_) || child_exit != ExitCode::Type::NotExited) {
        return;
    }

    handle_.close();
}

#endif // #if defined(TML_WINDOWS)
#endif //TML_HPP
