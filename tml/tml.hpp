
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
    #define ns(STR) (L##STR)
#else // POSIX
    #include <unistd.h>
    #include <csignal>
    #include <sys/wait.h>
    #include <sys/types.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <fcntl.h>
    #include <poll.h>
    #include <semaphore.h>
    #define ns(STR) ((const char*)u8##STR)
#endif

#if defined(__clang__) || defined(__GNUC__)
    #if defined(__clang__)
        #define TML_COMPILEDWITH_CLANG
    #else
        #define TML_COMPILEDWITH_GCC
    #endif
    #define TML_ATTR_NOINLINE    __attribute__((noinline))
    #define TML_ATTR_FORCEINLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
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
#include <cstdint>
#include <thread>
#include <functional>
#include <utility>
#include <variant>
#include <algorithm>
#include <array>
#include <chrono>

static_assert(sizeof(size_t) == 8,   "Only modern 64-bit architectures are allowed.");
static_assert(sizeof(unsigned) == 4, "Only modern 64-bit architectures are allowed.");

namespace tml {
    class Process;
    class OutputDevice;
    class Handle;
    class TMLException;
    class NamedPipe;
    class SharedRegion;
    class AlignedFlatBuffer;
    class Lock;
    struct ExitCode;
}

namespace tml {
    using AlignedBufferCallback = std::function<void(const AlignedFlatBuffer&)>;
    using DynamicBufferCallback = std::function<void(const std::vector<uint8_t>&)>;
    using OnExitCallback        = std::function<void(const ExitCode&)>;

    template<size_t len>
    using FlatBuffer = std::array<uint8_t, len>;

    template<typename T>
    concept BufferCallback =
        std::constructible_from<AlignedBufferCallback, T> ||
        std::constructible_from<DynamicBufferCallback, T>;

    template<typename T>
    concept Lockable = std::is_base_of_v<tml::Lock, T>;

    template<size_t>
    class NamedSemaphore;

    template<typename T> requires std::is_invocable_v<T>
    class ScopedAction;

    template<tml::Lockable T>
    class LockGuard;

#if defined(TML_WINDOWS)
    using NativeString = std::wstring;
    using NativeChar   = wchar_t;
    class NamedMutex;
#else
    using NativeString = std::string;
    using NativeChar   = char;
    using NamedMutex   = NamedSemaphore<1>;
#endif
}

namespace tml {
    std::string last_system_error();
    void spawn(const NativeString& name, const std::vector<NativeString>& args = {}, const NativeString& wd = ns(""));
    [[noreturn]] void _panic_impl(const std::string& file, int line, const std::string& msg = "");
}

namespace tml::this_process {
    [[nodiscard]] Handle get();
    [[nodiscard]] OutputDevice out();
    [[nodiscard]] OutputDevice err();
    [[nodiscard]] size_t get_id();
    [[noreturn]]  void kill(int status = 0);
}


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::DeferredAction ~
// - A very basic RAII wrapper around an invocable object.
// - Calls the invocable object when the destructor is invoked.
// - Comes with two macros, tml_defer, and tml_defer_if to make using the class cleaner.
////////////////////////////////////////////////////////////////////////////////////////////////////
template<typename T> requires std::is_invocable_v<T>
class tml::ScopedAction {
    T action_;
public:
    ~ScopedAction() { action_(); }

    ScopedAction(const ScopedAction&)             = delete;
    ScopedAction& operator=(const ScopedAction&)  = delete;
    ScopedAction(const ScopedAction&&)            = delete;
    ScopedAction& operator=(const ScopedAction&&) = delete;

    explicit ScopedAction(const T action) : action_(action) {}
};

#define tml_defer(action)               auto _ = tml::ScopedAction(action);
#define tml_defer_if(condition, action) \
auto _ = tml::ScopedAction([&](){       \
    if((condition)) action();           \
});                                     \


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::AlignedFlatBuffer ~
// - represents a page aligned, non-reallocatable block of virtual memory.
// - Preferred over tml::FlatBuffer when the size of the allocation cannot be known at compile time.
////////////////////////////////////////////////////////////////////////////////////////////////////
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
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::Handle {
public:
#if defined(TML_WINDOWS)
    using Value = ::HANDLE;
#else
    using Value = ::pid_t;
#endif

    void close();
    void invalidate();
    void kill() const;
    [[nodiscard]] ExitCode get_exit_code()  const noexcept;
    [[nodiscard]] Value get()               const noexcept;

    static bool is_invalid_handle_state(const Handle& handle);
    static bool is_invalid_handle_state(Value value);
    static Value get_invalid_handle_state();

    bool operator==(const Handle& other) const noexcept;
    bool operator==(Handle::Value other) const noexcept;
    bool operator!=(const Handle& other) const noexcept;
    bool operator!=(Handle::Value other) const noexcept;

    ~Handle() = default;
    explicit Handle(const Value value) : value_(value) {}
private:
    Value value_;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::ExitCode ~
// - represents the exit code of a child process.
// - the actual code value is DWORD on windows and int on linux.
////////////////////////////////////////////////////////////////////////////////////////////////////
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
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::OutputDevice {
public:
#if defined(TML_WINDOWS)
    using Value = ::HANDLE;
#else
    using Value = int;
#endif

    struct AnonymousPipe;
    enum class Type : uint8_t {
        None,       // Invalid
        File,       // Output device is a file on disk.
        PipeEnd,    // anonymous pipe. read or write end not specified.
        NamedPipe,  // bidirectional named pipe.
    };

    template<size_t out_size = 1024> FlatBuffer<out_size> read();
    template<size_t out_size = 1024> void read_into(FlatBuffer<out_size>& out);

    void close();
    void invalidate();
    [[nodiscard]] Value value() const;

    static auto get_invalid_handle_state()                         -> Value;
    static auto is_invalid_handle_state(Value value)               -> bool;
    static auto open_file(const NativeString& name, bool append)   -> OutputDevice;
    static auto create_file(const NativeString& name, bool append) -> OutputDevice;
    static auto create_pipe()                                      -> AnonymousPipe;

    bool operator==(const OutputDevice& other) const noexcept;
    bool operator==(OutputDevice::Value other) const noexcept;
    bool operator!=(const OutputDevice& other) const noexcept;
    bool operator!=(OutputDevice::Value other) const noexcept;

    ~OutputDevice() = default;
    OutputDevice() : value_(get_invalid_handle_state()) {}
    OutputDevice(const Value value) : value_(value) {}

private:
    Value value_{};
    Type  type_ = Type::None;
};

struct tml::OutputDevice::AnonymousPipe {
    OutputDevice read_end;
    OutputDevice write_end;
    ~AnonymousPipe() = default;
    AnonymousPipe()  = default;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::Lock ~
// - Base class for tml::NamedSemaphore and (on Windows) tml::NamedMutex
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::Lock {
public:
#if defined(TML_WINDOWS)
    using Value = ::HANDLE;
#else
    using Value = ::sem_t*;
#endif

    enum class Result : uint8_t {
        Acquired,  // The lock has been acquired by the calling thread.
        Blocked,   // Another thread has control over the lock, and it can't be acquired.
        Abandoned, // The owner of the lock was terminated before it could release it. The calling thread now owns this lock.
        BadCall,   // An argument is invalid, or you tried to acquire the lock on an invalid mutex or semaphore.
        Error,     // An error occurred while trying to acquire the lock, Check tml::last_system_error().
    };

    virtual Result try_lock() = 0;
    virtual Result lock()     = 0;
    virtual bool is_valid()   = 0;
    virtual void unlock()     = 0;
    virtual void destroy()    = 0;
    virtual void close()      = 0;

    static Value get_invalid_handle_state();
    static bool  is_invalid_handle_state(const Value val);

    Lock() : value_(get_invalid_handle_state()) {}
    virtual ~Lock() = default;
protected:
    Value value_;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::SharedRegion ~
// - A flat, anonymous region of virtual memory that is shared across processes.
// - Can be written to and read from by all processes that have the region open.
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::SharedRegion {
public:
#if defined(TML_WINDOWS)
    using RegionHandle = ::HANDLE;
#else
    using RegionHandle = int;
#endif

    template<typename T = void*>
    T get();
    const NativeString& name();
    void destroy();
    void close();
    [[nodiscard]] size_t size() const;
    [[nodiscard]] bool is_open() const;

    static bool         is_invalid_region_handle(RegionHandle h);
    static RegionHandle get_invalid_region_handle();
    static SharedRegion create(const NativeString& name, size_t max_length, size_t length = 0);
    static SharedRegion create_or_open(const NativeString& name, size_t max_length, size_t length = 0);
    static SharedRegion open(const NativeString& name, size_t length = 0);

    ~SharedRegion() = default;
private:
    static SharedRegion _create_impl(const NativeString&, size_t, bool open_if_exists, size_t);
    SharedRegion() : handle_(get_invalid_region_handle()) {}

    void*  addr_ = nullptr;
    size_t size_ = 0;
    RegionHandle handle_;
    NativeString name_;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::NamedSemaphore ~
// - An object that can be "locked" across different processes.
// - Constructor specifies the amount of processes that can lock the semaphore at once.
////////////////////////////////////////////////////////////////////////////////////////////////////
template<size_t num_slots>
class tml::NamedSemaphore final : public tml::Lock {
    static_assert(num_slots > 0);
    static_assert(num_slots < (std::numeric_limits<long>::max)());
public:

    Result lock()     override;
    Result try_lock() override;
    bool is_valid()   override;
    void unlock()     override;
    void destroy()    override;
    void close()      override;

    static NamedSemaphore create(const NativeString& name, bool immediate_lock = false);
    static NamedSemaphore open(const NativeString& name);
    static NamedSemaphore create_or_open(const NativeString& name, bool immediate_lock = false);

    NamedSemaphore()           = default;
    ~NamedSemaphore() override = default;
};


#if defined(TML_WINDOWS)
////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::NamedMutex ~
// - On Windows: an object that can be "locked" across different processes.
// - Can only be locked by one process at a time.
// - On POSIX systems, NamedMutex is an alias for NamedSemaphore<1> because mutexes are not IP.
// - This trick avoids having to do more complex things like map mutexes into shared memory.
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::NamedMutex final : public tml::Lock {
public:
    NamedMutex(NamedMutex&&)            noexcept;
    NamedMutex& operator=(NamedMutex&&) noexcept;

    Result try_lock() override;
    Result lock()     override;
    bool is_valid()   override;
    void unlock()     override;
    void destroy()    override;
    void close()      override;

    static NamedMutex create(const NativeString& name, bool immediate_lock = false);
    static NamedMutex create_or_open(const NativeString& name, bool immediate_lock = false);
    static NamedMutex open(const NativeString& name);

    ~NamedMutex() override = default;
private:
    NamedMutex() = default;
};
#endif


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::LockGuard ~
// - RAII wrapper around lockable IPC mechanisms.
// - Very similar to std::lock_guard.
// - the constructor locks the IPC primitive, and the destructor unlocks it.
////////////////////////////////////////////////////////////////////////////////////////////////////
template<tml::Lockable T>
class tml::LockGuard {
public:
    LockGuard(const LockGuard&)             = delete;
    LockGuard& operator=(const LockGuard&)  = delete;
    LockGuard(const LockGuard&&)            = delete;
    LockGuard& operator=(const LockGuard&&) = delete;

    bool has_lock() const;
    ~LockGuard()                 noexcept;
    explicit LockGuard(T&, bool) noexcept;
    explicit LockGuard(T&)       noexcept;
private:
    T& lock_;
    bool locked_ = false;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::NamedPipe ~
// - represents an IPC mechanism for sending messages between processes.
// - bidirectional if needed. Can be read and written to by any client.
// - only call NamedPipe::destroy() from the named pipe "server" process, i.e. the parent.
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::NamedPipe {
public:

    enum class AccessType : uint8_t {
        Read,   // Read-only mode: the calling thread is blocked until a writer connects.
        Write,  // The pipe cannot be read from by this process.
        Duplex  // The pipe can be written to and read from by this process. No blocking occurs on open.
    };

    template<size_t len = 1024>
    std::pair<bool, size_t> receive(FlatBuffer<len>& buff)       const noexcept;
    std::pair<bool, size_t> receive(void* buff, size_t len)      const noexcept;
    std::pair<bool, size_t> receive(std::vector<uint8_t>& buff)  const noexcept;
    std::pair<bool, size_t> receive(NativeString& buff, size_t len = 0) const noexcept;

    template<size_t len = 1024>
    std::pair<bool, size_t> send(FlatBuffer<len>& buff)         const noexcept;
    std::pair<bool, size_t> send(const void* buff, size_t len)  const noexcept;
    std::pair<bool, size_t> send(std::vector<uint8_t>& buff)    const noexcept;
    std::pair<bool, size_t> send(const NativeString& buff)      const noexcept;

    void on_receive(AlignedBufferCallback cb, size_t buff_len = 1024) const;
    void on_receive(DynamicBufferCallback cb, size_t buff_len = 1024) const;

    void close();
    void invalidate();
    bool destroy();
    [[nodiscard]] bool is_open() const;
    [[nodiscard]] const NativeString& name() const;

    static NamedPipe create(const NativeString& name, AccessType = AccessType::Duplex)  noexcept;
    static NamedPipe connect(const NativeString& name, AccessType = AccessType::Duplex) noexcept;

    ~NamedPipe() = default;
private:
    static void _on_receive_aligned_impl(AlignedBufferCallback cb, OutputDevice::Value value, size_t buff_len = 1024);
    static void _on_receive_dyn_impl(DynamicBufferCallback cb, OutputDevice::Value value, size_t buff_len = 1024);

    OutputDevice handle_;
    NativeString name_;
    NamedPipe() = default;
};


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ tml::TMLException (and friends) ~
// - represents a native operating system error.
// - thrown when certain serious errors occur, including:
// - process could not be started.
// - process could not be killed.
// - handle could not be closed.
////////////////////////////////////////////////////////////////////////////////////////////////////

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
////////////////////////////////////////////////////////////////////////////////////////////////////
class tml::Process {
public:
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&&) noexcept;
    Process& operator=(Process&&) noexcept;

    Process& args(const std::vector<NativeString>& arg_list);
    Process& args(std::vector<NativeString>&& arg_list);
    Process& working_directory(const NativeString& dir);
    Process& file_redirect(const NativeString& file_name, bool append_contents);
    Process& on_exit(OnExitCallback callback);
    Process& launch();
    ExitCode wait();

    [[nodiscard]] const std::vector<NativeString>& get_arguments() const;
    [[nodiscard]] const NativeString& get_name() const;
    [[nodiscard]] const NativeString& get_working_directory() const;
    [[nodiscard]] bool launched() const;
    [[nodiscard]] size_t get_id() const;
    [[nodiscard]] ExitCode get_exit_code();
    [[nodiscard]] bool exited();

    template<typename T> requires tml::BufferCallback<T>
    Process& buffer_redirect(size_t buff_size, T callback);

    ~Process();
    explicit Process(NativeString name)
    : handle_(Handle::get_invalid_handle_state()),
      name_(std::move(name)),
      callback_buffer_hint_(0),
#if defined(TML_MACOS) || defined(TML_LINUX)
      posix_cached_exit_code_(-1, ExitCode::Type::Unknown),
#endif
      output_(std::monostate()),
      output_callback_(std::monostate()),
      exit_callback_(std::monostate()){}

private:
#if defined(TML_MACOS) || defined(TML_LINUX)
    [[noreturn]] void _posix_child_launch_impl();
    void _posix_parent_launch_impl();
    static ExitCode _posix_blocking_wait_impl(Handle child_handle);
#endif

    static void _launch_pipe_aligned_read_impl(OutputDevice::Value, AlignedBufferCallback, size_t);
    static void _launch_pipe_dyn_read_impl(OutputDevice::Value, DynamicBufferCallback, size_t);
    static void _launch_exit_wait_impl(Handle child_handle, OnExitCallback cb);

    Handle handle_;
    NativeString name_;
    NativeString working_directory_;
    std::vector<NativeString> arguments_;
    size_t callback_buffer_hint_;

#if defined(TML_MACOS) || defined(TML_LINUX)
    ExitCode posix_cached_exit_code_;
#endif

    std::unique_ptr<std::thread> output_callback_worker_ = nullptr;
    std::unique_ptr<std::thread> exit_callback_worker_   = nullptr;

    std::variant<
        OutputDevice::AnonymousPipe,
        OutputDevice,
        std::monostate
    > output_;

    std::variant<
        AlignedBufferCallback,
        DynamicBufferCallback,
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
    ExitProcess(static_cast<UINT>(status));
}

[[nodiscard]] inline tml::OutputDevice
tml::this_process::out() {
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

[[nodiscard]] inline tml::OutputDevice
tml::this_process::err() {
    return GetStdHandle(STD_ERROR_HANDLE);
}

TML_ATTR_FORCEINLINE size_t
tml::this_process::get_id() {
    return static_cast<size_t>(GetCurrentProcessId());
}

TML_ATTR_FORCEINLINE tml::Handle
tml::this_process::get() {
    return Handle(GetCurrentProcess());
}

inline std::string
tml::last_system_error() {
    DWORD err_code = GetLastError();
    DWORD result   = 0;
    LPSTR outbuf   = nullptr;

    if(err_code == ERROR_SUCCESS) {
        return "";
    }

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

inline void
tml::spawn(const NativeString& name, const std::vector<NativeString>& args, const NativeString& wd) {

    //
    // if "name" or any string in "args" is empty,
    // we should reject this call right away.
    //

    if(std::ranges::find_if(args, [](const NativeString& arg) {
        return arg.empty();
    }) != args.end() || name.empty()) {
        SetLastError(ERROR_BAD_ARGUMENTS);
        throw TMLException::ProcessLaunchException();
    }

    const auto full = [&]() -> NativeString {
        NativeString full_ = name;
        for(const auto& arg : args) {
            full_ += ' ';
            full_ += arg;
        }
    }();

    //
    // Copy into a new temp buffer. See the Windows version of
    // tml::Process::launch() to see why we need to do this.
    //

    auto* tmp_arg_buff = new wchar_t[full.size() + 1];
    tml_defer([tmp_arg_buff] {
        delete[] tmp_arg_buff;
    });

    memcpy(tmp_arg_buff, full.data(), full.size());
    tmp_arg_buff[full.size()] = L'\0';

    //
    // Call CreateProcessW to spawn a child.
    //

    PROCESS_INFORMATION proc_info = { 0 };
    STARTUPINFOW        startup   = { 0 };
    startup.cb = sizeof(startup);
    if(!CreateProcessW(
        nullptr,
        tmp_arg_buff,
        nullptr,
        nullptr,
        FALSE,
        0,
        nullptr,
        wd.empty() ? nullptr : wd.c_str(),
        &startup,
        &proc_info
    )) {
        throw TMLException::ProcessLaunchException();
    }

    CloseHandle(proc_info.hThread);
    CloseHandle(proc_info.hProcess);
}


#else // OS == POSIX

[[noreturn]] TML_ATTR_FORCEINLINE void
tml::this_process::kill(const int status) {
    // this is NOT the same as C's exit(). Check man7 for more info.
    _exit(status);
}

[[nodiscard]] inline tml::OutputDevice
tml::this_process::out() {
    return OutputDevice(STDOUT_FILENO);
}

[[nodiscard]] inline tml::OutputDevice
tml::this_process::err() {
    return OutputDevice(STDERR_FILENO);
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
    NativeChar buffer[256] = { 0 };
    const int err_code     = errno;

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
// ~ Begin tml::NamedPipe methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

TML_ATTR_FORCEINLINE bool
tml::NamedPipe::is_open() const {
    return !Handle::is_invalid_handle_state(handle_.value());
}

TML_ATTR_FORCEINLINE void
tml::NamedPipe::close() {
    handle_.close();
}

TML_ATTR_FORCEINLINE void
tml::NamedPipe::invalidate() {
    handle_.invalidate();
}

TML_ATTR_FORCEINLINE const tml::NativeString&
tml::NamedPipe::name() const {
    return name_;
}

inline void
tml::NamedPipe::on_receive(TML_VALUE_PARAM AlignedBufferCallback cb, const size_t buff_len) const {
    if(!cb || !is_open()) {
        return;
    }
    std::thread(_on_receive_aligned_impl, cb, handle_.value(), buff_len).detach();
}

inline void
tml::NamedPipe::on_receive(TML_VALUE_PARAM DynamicBufferCallback cb, const size_t buff_len) const {
    if(!cb || !is_open()) {
        return;
    }
    std::thread(_on_receive_dyn_impl, cb, handle_.value(), buff_len).detach();
}


#if defined (TML_WINDOWS)

inline tml::NamedPipe
tml::NamedPipe::create(const NativeString &name, const AccessType access) noexcept {
    NamedPipe   pipe;
    const auto  full   = NativeString(L"(\\\\.\\pipe\\)") + name;
    const DWORD flags  = [&]() -> DWORD {
        switch(access) {
            case AccessType::Read:   return PIPE_ACCESS_INBOUND;
            case AccessType::Write:  return PIPE_ACCESS_OUTBOUND;
            default:                 return PIPE_ACCESS_DUPLEX;
        }
    }();

    pipe.handle_ = CreateNamedPipeW(
        full.c_str(),                    // Name of the pipe, must follow the "\\.\pipe\<NAME>" format
        flags,                           // Access modifier for this pipe (read/write/duplex)
        PIPE_TYPE_BYTE                   // Pipe is opened in byte stream mode rather than message mode.
          | PIPE_READMODE_BYTE           // Read operations treat data as a byte stream
          | PIPE_WAIT                    // Indicates that ReadFile and WriteFile should block.
          | PIPE_REJECT_REMOTE_CLIENTS,  // Reject remote clients (out of scope for this library)
        PIPE_UNLIMITED_INSTANCES,        // Unlimited concurrent connections
        1024,                            // Internal output (write) buffer size. Does not effect the amount of data you can write.
        1024,                            // Internal input (read) buffer size. Does not effect the amount of data you can write.
        0,                               // Timeout value. not relevant.
        nullptr                          // Pointer to an OVERLAPPED structure for overlapped IO. Not relevant.
    );

    // IMPORTANT:
    // Handle::is_invalid_handle_state checks for nullptr on Windows, NOT "INVALID_HANDLE_STATE".
    // This is a somewhat rare Win32 handle value, as usually NULL indicates an invalid handle state.
    // If we encounter it, we should generally just set the handle value to be nullptr
    // to indicate an invalid state to avoid any confusion.

    if(pipe.handle_ == INVALID_HANDLE_VALUE) {
        pipe.handle_ = nullptr;
        return pipe;
    }

    if(access == AccessType::Read) {
        ConnectNamedPipe(pipe.handle_.value(), nullptr);
    }

    pipe.name_ = full;
    return pipe;
}

inline tml::NamedPipe
tml::NamedPipe::connect(const NativeString &name, const AccessType access) noexcept {
    NamedPipe   pipe;
    const auto  full   = NativeString(L"(\\\\.\\pipe\\)") + name;
    const DWORD flags  = [&]() -> DWORD {
        switch(access) {
            case AccessType::Read:   return GENERIC_READ;
            case AccessType::Write:  return GENERIC_WRITE;
            default:                 return GENERIC_READ | GENERIC_WRITE;
        }
    }();

    pipe.handle_ = CreateFileW(
        full.c_str(),
        flags,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,         // File MUST already exist. Do not create one if it doesn't.
        0,                     // No file attribute flags.
        nullptr
    );

    if(pipe.handle_ == INVALID_HANDLE_VALUE) {
        pipe.handle_ = nullptr;
        return pipe;
    }

    if(access == AccessType::Read) {
        WaitNamedPipeW(full.c_str(), NMPWAIT_WAIT_FOREVER);
    }

    pipe.name_ = full;
    return pipe;
}

inline void
tml::NamedPipe::_on_receive_aligned_impl(
    TML_VALUE_PARAM AlignedBufferCallback cb,
    TML_VALUE_PARAM const OutputDevice::Value value,
    TML_VALUE_PARAM size_t buff_len
) {
    if(buff_len == 0) {
        buff_len = 1024;
    }

    DWORD bytes_read = 0;
    const AlignedFlatBuffer buffer(buff_len);
    while(ReadFile(
        value,
        buffer.data(),
        buffer.size(),
        &bytes_read,
        nullptr
    ) && bytes_read > 0) {
        cb(buffer);
        memset(buffer.data(), '\0', buffer.size());
    }
}

inline void
tml::NamedPipe::_on_receive_dyn_impl(
    TML_VALUE_PARAM DynamicBufferCallback cb,
    TML_VALUE_PARAM const OutputDevice::Value value,
    TML_VALUE_PARAM size_t buff_len
) {
    if(buff_len == 0) {
        buff_len = 1024;
    }

    std::vector<uint8_t> buffer(buff_len);
    DWORD bytes_read = 0;
    while(ReadFile(
        value,
        buffer.data(),
        buffer.size(),
        &bytes_read,
        nullptr
    ) && bytes_read > 0) {
        buffer.resize(static_cast<size_t>(bytes_read));
        cb(buffer);
        buffer.resize(buff_len);
        std::ranges::fill(buffer, '\0');
    }
}

inline bool
tml::NamedPipe::destroy() {
    if(name_.empty()) {
        return false;
    }

    // Note: if NamedPipe::destroy() on Windows is called from a "client" process,
    // this function has NO effect whatsoever. DisconnectNamedPipe will fail,
    // because handle_ will not be a named pipe handle, it will be a handle
    // to a file object, which behaves differently.
    // If this function is called from the named pipe "server" process,
    // It will boot all waiting clients off of the pipe if there are any,
    // before closing the handle. On Windows, once all handles to a named pipe are closed,
    // it is deleted. For this reason, we do not call DeleteFile or attempt to delete
    // the named pipe manually, unlike with a POSIX NamedPipe where we call unlink().

    DisconnectNamedPipe(handle_.value());
    handle_.close();
    return true;
}

inline std::pair<bool, size_t>
tml::NamedPipe::receive(std::vector<uint8_t> &buff) const noexcept {
    if(buff.empty() || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_read  = 0;
    const BOOL result = ReadFile(
        handle_.value(),
        buff.data(),
        static_cast<DWORD>(buff.size()),
        &bytes_read,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_read));
}

inline std::pair<bool, size_t>
tml::NamedPipe::receive(NativeString &buff, const size_t len) const noexcept {
    if(len != 0) {
        buff.resize(len);
    }
    if(!is_open() || buff.empty()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_read  = 0;
    const BOOL result = ReadFile(
        handle_.value(),
        buff.data(),
        static_cast<DWORD>(buff.size()),
        &bytes_read,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_read));
}

template<size_t len>
auto tml::NamedPipe::receive(FlatBuffer<len> &buff) const noexcept -> std::pair<bool, size_t> {
    if(len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_read  = 0;
    const BOOL result = ReadFile(
        handle_.value(),
        buff.data(),
        static_cast<DWORD>(buff.size()),
        &bytes_read,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_read));
}

inline std::pair<bool, size_t>
tml::NamedPipe::receive(void* const buff, const size_t len) const noexcept {
    if(buff == nullptr || len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_read  = 0;
    const BOOL result = ReadFile(
        handle_.value(),
        buff,
        static_cast<DWORD>(len),
        &bytes_read,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_read));
}

inline std::pair<bool, size_t>
tml::NamedPipe::send(const void *buff, const size_t len) const noexcept {
    if(buff == nullptr || len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_wrote = 0;
    const BOOL result = WriteFile(
        handle_.value(),
        buff,
        static_cast<DWORD>(len),
        &bytes_wrote,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_wrote));
}

inline std::pair<bool, size_t>
tml::NamedPipe::send(std::vector<uint8_t> &buff) const noexcept {
    if(buff.empty() || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_wrote = 0;
    const BOOL result = WriteFile(
        handle_.value(),
        buff.data(),
        static_cast<DWORD>(buff.size()),
        &bytes_wrote,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_wrote));
}

inline std::pair<bool, size_t>
tml::NamedPipe::send(const NativeString &buff) const noexcept {
    if(buff.empty() || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_wrote = 0;
    const BOOL result = WriteFile(
        handle_.value(),
        buff.data(),
        static_cast<DWORD>(buff.size()),
        &bytes_wrote,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_wrote));
}

template<size_t len>
auto tml::NamedPipe::send(FlatBuffer<len> &buff) const noexcept -> std::pair<bool, size_t> {
    if(len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    DWORD bytes_wrote = 0;
    const BOOL result = WriteFile(
        handle_.value(),
        buff.data(),
        static_cast<DWORD>(buff.size()),
        &bytes_wrote,
        nullptr
    );

    return result == FALSE
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(bytes_wrote));
}


#else // OS == POSIX

inline tml::NamedPipe
tml::NamedPipe::create(const NativeString &name, const AccessType access) noexcept{
    const auto full = NativeString("/tmp/TML_NAMED_PIPE_") + name;
    NamedPipe pipe;

    if(::mkfifo(full.c_str(), 0666) == -1) {
        return pipe;
    }

    const int flags = [&]() -> int {
       switch(access) {
           case AccessType::Read:  return O_RDONLY;
           case AccessType::Write: return O_WRONLY;
           default:                return O_RDWR;
       }
    }();

    pipe.handle_ = OutputDevice(::open(full.c_str(), flags));
    pipe.name_   = full;
    return pipe;
}

inline tml::NamedPipe
tml::NamedPipe::connect(const NativeString &name, const AccessType access) noexcept {
    const auto  full      = NativeString("/tmp/TML_NAMED_PIPE_") + name;
    struct stat file_info = { 0 };
    NamedPipe pipe;

    if(::stat(full.c_str(), &file_info) == -1) {
        return pipe;
    }

    if(!(S_ISFIFO(file_info.st_mode))) {
        errno = EINVAL;
        return pipe;
    }

    const int flags = [&]() -> int {
        switch(access) {
            case AccessType::Read:  return O_RDONLY;
            case AccessType::Write: return O_WRONLY;
            default:                return O_RDWR;
        }
    }();

    pipe.handle_ = OutputDevice(::open(full.c_str(), flags));
    pipe.name_   = full;
    return pipe;
}

inline std::pair<bool, size_t>
tml::NamedPipe::receive(std::vector<uint8_t>& buff) const noexcept {
    if(buff.empty() || !is_open()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLIN;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
        return std::make_pair(false, 0);
    }

    const auto result = ::read(handle_.value(), buff.data(), buff.size());
    return result == -1
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(result));
}

inline std::pair<bool, size_t>
tml::NamedPipe::receive(void* const buff, const size_t len) const noexcept {
    if(len == 0 || !is_open() || buff == nullptr) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLIN;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
        return std::make_pair(false, 0);
    }

    const auto result = ::read(handle_.value(), buff, len);
    return result == -1
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true,  static_cast<size_t>(result));
}

template<size_t len>
auto tml::NamedPipe::receive(FlatBuffer<len>& buff) const noexcept -> std::pair<bool, size_t> {
    if(len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLIN;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
        return std::make_pair(false, 0);
    }

    const auto result = ::read(handle_.value(), buff.data(), buff.size());
    return result == -1
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true, static_cast<size_t>(result));
}

inline std::pair<bool, size_t>
tml::NamedPipe::receive(NativeString& buff, const size_t len) const noexcept {
    if(len != 0) {
        buff.resize(len);
    }
    if(!is_open() || buff.empty()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLIN;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
        return std::make_pair(false, 0);
    }

    const auto result = ::read(handle_.value(), buff.data(), buff.size());
    if(result < 0) {
        return std::make_pair(false, 0);
    }
    if(result < buff.size()) {
        buff[result] = '\0';
    }
    else {
        buff.back() = '\0';
    }

    return std::make_pair(true, result);
}

inline std::pair<bool, size_t>
tml::NamedPipe::send(const void* buff, const size_t len) const noexcept {
    if(buff == nullptr || len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLOUT;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLOUT)) {
        return std::make_pair(false, 0);
    }

    const auto result = ::write(handle_.value(), buff, len);
    return result == -1
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true, static_cast<size_t>(result));
}

inline std::pair<bool, size_t>
tml::NamedPipe::send(std::vector<uint8_t>& buff) const noexcept {
    if(buff.empty() || !is_open()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLOUT;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLOUT)) {
        return std::make_pair(false, 0);
    }

    const auto result =  ::write(handle_.value(), buff.data(), buff.size());
    return result == -1
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true, static_cast<size_t>(result));
}

inline std::pair<bool, size_t>
tml::NamedPipe::send(const NativeString& buff) const noexcept {
    if(buff.empty() || !is_open()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLOUT;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLOUT)) {
        return std::make_pair(false, 0);
    }

    const auto result =  ::write(handle_.value(), buff.data(), buff.size());
    return result == -1
      ? std::make_pair(false, static_cast<size_t>(0))
      : std::make_pair(true, static_cast<size_t>(result));
}

template<size_t len>
auto tml::NamedPipe::send(FlatBuffer<len> &buff) const noexcept -> std::pair<bool, size_t> {
    if(len == 0 || !is_open()) {
        return std::make_pair(false, 0);
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = handle_.value();
    fds[0].events = POLLOUT;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLOUT)) {
        return std::make_pair(false, 0);
    }

    const auto result = ::write(handle_.value(), buff.data(), buff.size());
    return result == -1
      ? std::make_pair(false, 0)
      : std::make_pair(true, result);
}

inline void
tml::NamedPipe::_on_receive_dyn_impl(
    TML_VALUE_PARAM DynamicBufferCallback cb,
    TML_VALUE_PARAM const OutputDevice::Value value,
    TML_VALUE_PARAM size_t buff_len
) {
    if(buff_len == 0) {
        buff_len = 1024;
    }

    std::vector<uint8_t> buffer(buff_len);
    pollfd fds[1] = { 0 };
    fds[0].fd     = value;
    fds[0].events = POLLIN;

    while(true) {
        if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
            break;
        }

        fds[0].revents = 0;
        const auto read_res = ::read(value, buffer.data(), buffer.size());
        if(read_res <= 0) {
            break;
        }

        buffer.resize(static_cast<size_t>(read_res));
        cb(buffer);
        buffer.resize(buff_len);
        std::ranges::fill(buffer, '\0');
    }
}

inline void
tml::NamedPipe::_on_receive_aligned_impl(
    TML_VALUE_PARAM AlignedBufferCallback cb,
    TML_VALUE_PARAM const OutputDevice::Value value,
    TML_VALUE_PARAM size_t buff_len
) {
    if(buff_len == 0) {
        buff_len = 1024;
    }

    const AlignedFlatBuffer buffer(buff_len);
    pollfd fds[1] = { 0 };
    fds[0].fd     = value;
    fds[0].events = POLLIN;

    while(true) {
        if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
            break;
        }

        fds[0].revents = 0;
        if(::read(value, buffer.data(), buffer.size()) <= 0) {
            break;
        }

        cb(buffer);
        memset(buffer.data(), '\0', buffer.size());
    }
}

inline bool
tml::NamedPipe::destroy() {
    if(name_.empty()) {
        return false;
    }

    if(is_open()) {
        handle_.close();
        handle_.invalidate();
    }

    ::unlink(name_.c_str());
    return true;
}

#endif // #if defined (TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::Handle methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

inline bool
tml::Handle::operator!=(const Handle &other) const noexcept {
    return this->value_ != other.value_;
}

inline bool
tml::Handle::operator!=(const Handle::Value other) const noexcept {
    return this->value_ != other;
}

inline bool
tml::Handle::operator==(const Handle &other) const noexcept {
    return this->value_ == other.value_;
}

inline bool
tml::Handle::operator==(const Handle::Value other) const noexcept {
    return this->value_ == other;
}

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

TML_ATTR_FORCEINLINE tml::Handle::Value
tml::Handle::get_invalid_handle_state() {
    return nullptr;
}

TML_ATTR_FORCEINLINE void
tml::Handle::kill() const {
    if(!::TerminateProcess(value_, 0)) {
        throw TMLException::ProcessTerminationException();
    }
}

inline void
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
    if(!GetExitCodeProcess(value_, &exit_code)) {
        return {0, ExitCode::Type::Unknown};
    }
    if(exit_code == STILL_ACTIVE) {
        return {exit_code, ExitCode::Type::NotExited };
    }

    return {exit_code, ExitCode::Type::Normal};
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

inline bool
tml::OutputDevice::operator!=(const OutputDevice &other) const noexcept {
    return this->value_ != other.value_;
}

inline bool
tml::OutputDevice::operator!=(const OutputDevice::Value other) const noexcept {
    return this->value_ != other;
}

inline bool
tml::OutputDevice::operator==(const OutputDevice &other) const noexcept {
    return this->value_ == other.value_;
}

inline bool
tml::OutputDevice::operator==(const OutputDevice::Value other) const noexcept {
    return this->value_ == other;
}

inline void
tml::OutputDevice::invalidate() {
    value_ = get_invalid_handle_state();
    type_  = Type::None;
}

[[nodiscard]] inline tml::OutputDevice::Value
tml::OutputDevice::value() const {
    return value_;
}

#if defined(TML_WINDOWS)

template<size_t out_size>
auto tml::OutputDevice::read() -> tml::FlatBuffer<out_size> {
    FlatBuffer<out_size> buffer;
    if(!ReadFile(
        value_,          // file handle.
        buffer.data(),   // pointer to receive bytes.
        buffer.size(),   // # of bytes to read
        nullptr,         // out parameter for bytes read. Optional.
        nullptr          // ptr to OVERLAPPED structure for async io. Optional.
    )) {
        throw TMLException::OutputDeviceReadException();
    }

    return buffer;
}

template<size_t out_size>
auto tml::OutputDevice::read_into(FlatBuffer<out_size> &out) -> void {
    if(!ReadFile(
        value_,
        out.data(),
        out.size(),
        nullptr,
        nullptr
    )) {
        throw TMLException::OutputDeviceReadException();
    }
}

TML_ATTR_FORCEINLINE tml::OutputDevice::Value
tml::OutputDevice::get_invalid_handle_state() {
    return nullptr;
}

inline void
tml::OutputDevice::close() {
    CancelIoEx(value_, nullptr);
    if(is_invalid_handle_state(value_) || !CloseHandle(value_)) {
        return;
    }

    value_ = get_invalid_handle_state();
}

TML_ATTR_FORCEINLINE bool
tml::OutputDevice::is_invalid_handle_state(const Value value) {
    return value == nullptr || value == INVALID_HANDLE_VALUE;
}

inline tml::OutputDevice
tml::OutputDevice::create_file(const NativeString& name, const bool append) {
    OutputDevice device;
    DWORD flags = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    if(append) {
        flags |= FILE_APPEND_DATA;
    }

    device.type_  = Type::File;
    device.value_ = CreateFileW(
        name.c_str(),                        // Name of the file.
        flags,                               // Access flags.
        FILE_SHARE_READ                      // Other processes can read from this file at the same time.
          | FILE_SHARE_WRITE                 // Other processes can write to this file at the same time.
          | FILE_SHARE_DELETE,               // Other processes can delete this file while it's open here.
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

inline auto
tml::OutputDevice::open_file(const NativeString &name, const bool append) -> OutputDevice {
    OutputDevice device;
    DWORD flags = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    if(append) {
        flags |= FILE_APPEND_DATA;
    }

    device.type_  = Type::File;
    device.value_ = CreateFileW(
        name.c_str(),
        flags,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if(device.value_ == INVALID_HANDLE_VALUE) {
        throw TMLException::OutputDeviceCreationException();
    }

    if(append) {
        SetFilePointer(device.value_, 0, nullptr, FILE_END);
    }

    return device;
}

inline tml::OutputDevice::AnonymousPipe
tml::OutputDevice::create_pipe() {
    AnonymousPipe pipe;
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
    if(is_invalid_handle_state(value_) || ::close(value_) == -1) {
        return;
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
tml::OutputDevice::create_file(const NativeString& name, const bool append) {
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

inline auto
tml::OutputDevice::open_file(const NativeString &name, const bool append) -> OutputDevice {
    OutputDevice device;
    int flags = O_RDWR;
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

inline tml::OutputDevice::AnonymousPipe
tml::OutputDevice::create_pipe() {
    int fd[2] = { 0 };
    if(pipe(fd) == -1) {
        throw TMLException::OutputDeviceCreationException();
    }

    AnonymousPipe pipe;
    pipe.read_end.value_  = fd[0];
    pipe.write_end.value_ = fd[1];
    pipe.read_end.type_   = Type::PipeEnd;
    pipe.write_end.type_  = Type::PipeEnd;
    return pipe;
}

template<size_t out_size>
auto tml::OutputDevice::read() -> FlatBuffer<out_size> {
    auto   out    = FlatBuffer<out_size>();
    pollfd fds[1] = { 0 };
    fds[0].fd     = value_;
    fds[0].events = POLLIN;

    std::fill(out.begin(), out.end(), '\0');
    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
        throw TMLException::OutputDeviceReadException();
    }

    if(::read(value_, out.data(), out.size()) == -1) {
        throw TMLException::OutputDeviceReadException();
    }

    return out;
}

template<size_t out_size>
auto tml::OutputDevice::read_into(FlatBuffer<out_size>& out) -> void {
    pollfd fds[1] = { 0 };
    fds[0].fd     = value_;
    fds[0].events = POLLIN;

    if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
        throw TMLException::OutputDeviceReadException();
    }

    if(::read(value_, out.data(), out.size()) == -1) {
        throw TMLException::OutputDeviceReadException();
    }
}

#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::Lockable methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

#if defined(TML_WINDOWS)
TML_ATTR_FORCEINLINE tml::Lock::Value
tml::Lock::get_invalid_handle_state() {
    return nullptr;
}

TML_ATTR_FORCEINLINE bool
tml::Lock::is_invalid_handle_state(const Value val) {
    return val == nullptr;
}

#else // OS == POSIX

TML_ATTR_FORCEINLINE tml::Lockable::Value
tml::Lockable::get_invalid_handle_state() {
    return SEM_FAILED;
}

TML_ATTR_FORCEINLINE bool
tml::Lockable::is_invalid_handle_state(const Value val) {
    return val == SEM_FAILED;
}
#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::LockGuard methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

template<tml::Lockable T>
tml::LockGuard<T>::LockGuard(T& lock) noexcept : lock_(lock) {
    if(!lock_.is_valid()) {
        return;
    }

    locked_ = lock_.lock() == Lock::Result::Acquired;
}

template<tml::Lockable T>
tml::LockGuard<T>::LockGuard(T& lock, const bool try_lock) noexcept : lock_(lock) {
    if(!lock_.is_valid()) {
        return;
    }

    Lock::Result res;
    if(try_lock) {
        res = lock_.try_lock();
    } else {
        res = lock_.lock();
    }

    locked_ = res == Lock::Result::Acquired;
}

template<tml::Lockable T>
tml::LockGuard<T>::~LockGuard() noexcept {
    if(locked_) lock_.unlock();
}

template<tml::Lockable T>
auto tml::LockGuard<T>::has_lock() const -> bool {
    return locked_;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::NamedSemaphore methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

#if defined(TML_WINDOWS)

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::close() -> void {
    if(is_invalid_handle_state(value_)) {
        return;
    }

    CloseHandle(value_);
    value_ = get_invalid_handle_state();
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::destroy() -> void {
    close();
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::is_valid() -> bool {
    return Lock::is_invalid_handle_state(value_);
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::unlock() -> void {
    if(is_invalid_handle_state(value_)) {
        return;
    }

    ReleaseSemaphore(value_, 1, nullptr);
}

/* NOTE (Windows):
 * NamedSemaphore::lock() and try_lock() are essentially
 * identical to NamedMutex::lock() because the way you lock them
 * using win32 is identical. This is kind of lazy, and I could
 * implement some templated solution for this, or have these functions
 * exist in the base class instead, but I think that would mess with the POSIX
 * side of things. Keeping it this way for now.
 */

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::lock() -> Result {
    if(is_invalid_handle_state(value_)) {
        return Result::BadCall;
    }

    switch(WaitForSingleObject(value_, INFINITE)) {
        case WAIT_OBJECT_0:  return Result::Acquired;
        case WAIT_ABANDONED: return Result::Abandoned;
        default:             return Result::Error;
    }
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::try_lock() -> Result {
    if(is_invalid_handle_state(value_)) {
        return Result::BadCall;
    }

    switch(WaitForSingleObject(value_, 0)) {
        case WAIT_OBJECT_0:  return Result::Acquired;
        case WAIT_TIMEOUT:   return Result::Blocked;
        case WAIT_ABANDONED: return Result::Abandoned;
        default:             return Result::Error;
    }
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::create(const NativeString& name, const bool immediate_lock) -> NamedSemaphore {
    NamedSemaphore<num_slots> sem;
    const auto full = NativeString(L"Local\\") + name;

    sem.value_ = CreateSemaphoreW(
        nullptr,
        static_cast<LONG>(num_slots),
        static_cast<LONG>(num_slots),
        full.c_str()
    );

    if(sem.value_ == nullptr || GetLastError() == ERROR_ALREADY_EXISTS) {
        sem.close();
        return sem;
    }
    if(immediate_lock && WaitForSingleObject(sem.value_, INFINITE) != WAIT_OBJECT_0) {
        sem.close();
    }

    return sem;
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::open(const NativeString &name) -> NamedSemaphore {
    NamedSemaphore<num_slots> sem;
    const auto full = NativeString(L"Local\\") + name;

    sem.value_ = OpenSemaphoreW(  // Call only succeeds if the semaphore exists.
        SEMAPHORE_MODIFY_STATE    // For ReleaseSemaphore.
         | SYNCHRONIZE,           // For WaitForSingleObject.
        FALSE,                    // Do not inherit this handle in child processes.
        full.c_str()              // Semaphore name (with "Local\" prefix)
    );
    return sem;
}

template<size_t num_slots>
auto tml::NamedSemaphore<num_slots>::create_or_open(const NativeString &name, const bool immediate_lock) -> NamedSemaphore {
    NamedSemaphore<num_slots> sem;
    const auto full = NativeString(L"Local\\") + name;

    sem.value_ = CreateSemaphoreW(
        nullptr,
        static_cast<LONG>(num_slots),
        static_cast<LONG>(num_slots),
        full.c_str()
    );

    if(sem.value_ == nullptr) {
        return sem;
    }
    if(immediate_lock && WaitForSingleObject(sem.value_, INFINITE) != WAIT_OBJECT_0) {
        sem.close();
    }

    return sem;
}

#else // OS == POSIX
// TODO

#endif


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::NamedMutex methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

#if defined(TML_WINDOWS) // Class does not exist for POSIX

inline
tml::NamedMutex::NamedMutex(NamedMutex&& other) noexcept : Lock() {
    value_       = other.value_;
    other.value_ = get_invalid_handle_state();
}

inline tml::NamedMutex&
tml::NamedMutex::operator=(NamedMutex&& other) noexcept {
    value_       = other.value_;
    other.value_ = get_invalid_handle_state();
    return *this;
}

inline tml::Lock::Result
tml::NamedMutex::lock() {
    if(is_invalid_handle_state(value_)) {
        return Result::BadCall;
    }

    switch(WaitForSingleObject(value_, INFINITE)) {
        case WAIT_OBJECT_0:  return Result::Acquired;
        case WAIT_ABANDONED: return Result::Abandoned;
        default:             return Result::Error;
    }
}

inline tml::Lock::Result
tml::NamedMutex::try_lock() {
    if(is_invalid_handle_state(value_)) {
        return Result::BadCall;
    }

    switch(WaitForSingleObject(value_, 0)) {
        case WAIT_OBJECT_0:  return Result::Acquired;
        case WAIT_TIMEOUT:   return Result::Blocked;
        case WAIT_ABANDONED: return Result::Abandoned;
        default:             return Result::Error;
    }
}

inline void
tml::NamedMutex::unlock() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    ReleaseMutex(value_);
}

TML_ATTR_FORCEINLINE void
tml::NamedMutex::close() {
    if(!Lock::is_invalid_handle_state(value_)) {
        CloseHandle(value_);
        value_ = get_invalid_handle_state();
    }
}

TML_ATTR_FORCEINLINE bool
tml::NamedMutex::is_valid() {
    return Lock::is_invalid_handle_state(value_);
}

TML_ATTR_FORCEINLINE void
tml::NamedMutex::destroy() {
    close();
}

inline tml::NamedMutex
tml::NamedMutex::create(const NativeString& name, const bool immediate_lock) {
    NamedMutex mtx;
    mtx.value_ = CreateMutexW(
        nullptr,
        immediate_lock ? TRUE : FALSE,
        name.c_str()
    );

    if(GetLastError() == ERROR_ALREADY_EXISTS) {
        if(immediate_lock) mtx.unlock();
        mtx.close();
    }
    return mtx;
}

inline tml::NamedMutex
tml::NamedMutex::open(const NativeString &name) {
    NamedMutex mtx;
    const auto full = NativeString(L"Local\\") + name;

    mtx.value_ = OpenMutexW(  // Call only succeeds if the mutex exists.
        MUTEX_MODIFY_STATE    // For WaitForSingleObject.
         | SYNCHRONIZE,       // For ReleaseMutex.
        FALSE,                // Child processes do not inherit this mutex handle.
        full.c_str()          // Full name of the mutex.
    );
    return mtx;
}

inline tml::NamedMutex
tml::NamedMutex::create_or_open(const NativeString &name, const bool immediate_lock) {
    NamedMutex mtx;
    mtx.value_ = CreateMutexW(
        nullptr,
        immediate_lock ? TRUE : FALSE,
        name.c_str()
    );

    return mtx;
}

#endif // #if defined(TML_WINDOWS)


////////////////////////////////////////////////////////////////////////////////////////////////////
// ~ Begin tml::SharedRegion methods. ~
////////////////////////////////////////////////////////////////////////////////////////////////////

template<typename T>
auto tml::SharedRegion::get() -> T {
    constexpr bool is_valid_ptr = std::is_pointer_v<T>;
    constexpr bool is_void_ptr  = std::is_same_v<T, void*>;
    static_assert(is_valid_ptr || is_void_ptr, "T must be a valid pointer type.");
    return reinterpret_cast<T>(addr_);
}

inline bool
tml::SharedRegion::is_open() const {
    return !is_invalid_region_handle(handle_) && addr_ != nullptr;
}

inline size_t
tml::SharedRegion::size() const {
    return size_;
}

inline const tml::NativeString&
tml::SharedRegion::name() {
    return name_;
}


#if defined(TML_WINDOWS)

TML_ATTR_FORCEINLINE
auto tml::SharedRegion::get_invalid_region_handle() -> RegionHandle {
    return nullptr;
}

TML_ATTR_FORCEINLINE
auto tml::SharedRegion::is_invalid_region_handle(const RegionHandle h) -> bool {
    return h == get_invalid_region_handle();
}

inline void
tml::SharedRegion::close() {
    if(addr_   != nullptr) UnmapViewOfFile(addr_);
    if(handle_ != nullptr) CloseHandle(handle_);
    addr_   = nullptr;
    handle_ = nullptr;
}

inline void
tml::SharedRegion::destroy() {
    /* On Windows, there is no way to
     * manually destroy a file mapping object.
     * These objects are destroyed once their reference count
     * reaches zero. That is, when the last process
     * that has opened a handle to that object closes it.
     * This differs on POSIX systems where you can call
     * unlink() to delete the underlying file.
    */
    close();
}

inline tml::SharedRegion
tml::SharedRegion::_create_impl(
    const NativeString& name,
    const size_t max_length,
    const bool open_if_exists,
    const size_t length
) {
    auto sr         = SharedRegion();
    bool state      = false;
    const auto full = NativeString(L"Local\\") + name;

    if(max_length == 0) {
        SetLastError(ERROR_BAD_ARGUMENTS);
        return sr;
    }

    tml_defer_if(!state && sr.handle_ != nullptr, [&] {
      CloseHandle(sr.handle_);
      sr.handle_ = nullptr;
    });

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Create shared memory object.

    sr.handle_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE,                                   // Indicates that we are creating this object from the pagefile.
        nullptr,                                                // attributes. Optional.
        PAGE_READWRITE,                                         // memory permissions for the object. R/W.
        static_cast<DWORD>((max_length >> 32) & 0xFFFFFFFFU),   // high order 32 bits of the object's maximum size.
        static_cast<DWORD>(max_length & 0xFFFFFFFFU),           // low order 32 bits of the object's maximum size.
        full.c_str()                                            // name of the object.
    );

    if(sr.handle_ == nullptr || (GetLastError() == ERROR_ALREADY_EXISTS && !open_if_exists)) {
        return sr;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Map a "view" of the object into this process' address space.

    if(sr.addr_ = MapViewOfFile(
        sr.handle_,               // Object handle
        FILE_MAP_ALL_ACCESS,      // Indicates we want a read/write view.
        0,                        // high order view offset. Not relevant.
        0,                        // low order view offset. Not relevant.
        length                    // how many bytes to map. If 0, maps the whole thing.
    ); sr.addr_ != nullptr) {
        state = true;
    }

    return sr;
}

inline tml::SharedRegion
tml::SharedRegion::open(const NativeString &name, const size_t length) {
    auto sr         = SharedRegion();
    bool state      = false;
    const auto full = NativeString(L"Local\\") + name;

    tml_defer_if(!state && sr.handle_ != nullptr, [&] {
        CloseHandle(sr.handle_);
        sr.handle_ = nullptr;
    });

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Open the existing shared memory object.

    sr.handle_ = OpenFileMappingW(
        FILE_MAP_ALL_ACCESS,        // Why do we need to specify this? MapViewOfFile already requires this...
        FALSE,                      // Do not inherit this handle in child processes.
        full.c_str()                // Object name, prefixed with Local\.
    );

    if(sr.handle_ == nullptr) {
        return sr;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Map a view of the object into this process' address space.

    if(sr.addr_ = MapViewOfFile(
        sr.handle_,
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        length
    ); sr.addr_ != nullptr) {
        state = true;
    }

    return sr;
}

TML_ATTR_FORCEINLINE tml::SharedRegion
tml::SharedRegion::create(const NativeString& name, const size_t max_length, const size_t length) {
    return _create_impl(name, max_length, false, length);
}

TML_ATTR_FORCEINLINE tml::SharedRegion
tml::SharedRegion::create_or_open(const NativeString &name, const size_t max_length, const size_t length) {
    return _create_impl(name, max_length, true, length);
}

#else  // OS == POSIX
//TODO
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

[[nodiscard]] TML_ATTR_FORCEINLINE const std::vector<tml::NativeString>&
tml::Process::get_arguments() const {
    return arguments_;
}

[[nodiscard]] TML_ATTR_FORCEINLINE const tml::NativeString&
tml::Process::get_name() const {
    return name_;
}

[[nodiscard]] TML_ATTR_FORCEINLINE const tml::NativeString&
tml::Process::get_working_directory() const {
    return working_directory_;
}

[[nodiscard]] TML_ATTR_FORCEINLINE bool
tml::Process::launched() const {
    return !Handle::is_invalid_handle_state(handle_);
}

TML_ATTR_FORCEINLINE tml::Process&
tml::Process::args(const std::vector<NativeString>& arg_list) {
    arguments_ = arg_list;
    return *this;
}

TML_ATTR_FORCEINLINE tml::Process&
tml::Process::args(std::vector<NativeString>&& arg_list) {
    arguments_ = arg_list;
    return *this;
}

inline tml::Process&
tml::Process::working_directory(const NativeString &dir) {
    namespace fs = std::filesystem;

    if(!fs::exists(dir)) {
        throw TMLException("working_directory(): path does not exist.", TMLException::Type::FileSystemException);
    }
    if(!is_directory(fs::path(dir))) {
        throw TMLException("working_directory(): path is not a directory.", TMLException::Type::FileSystemException);
    }

    working_directory_ = dir;
    return *this;
}

template<typename T> requires tml::BufferCallback<T>
auto tml::Process::buffer_redirect(const size_t buff_size, T callback) -> Process& {
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
tml::Process::file_redirect(const NativeString& file_name, const bool append_contents) {
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

TML_ATTR_FORCEINLINE tml::ExitCode
tml::Process::get_exit_code() {
    return handle_.get_exit_code();
}

TML_ATTR_FORCEINLINE bool
tml::Process::exited() {
    return handle_.get_exit_code().type == ExitCode::Type::NotExited;
}

TML_ATTR_FORCEINLINE tml::ExitCode
tml::Process::wait() {
    if(WaitForSingleObject(handle_.get(), INFINITE) == WAIT_FAILED) {
        return {0, ExitCode::Type::Unknown};
    }

    return handle_.get_exit_code();
}

inline size_t
tml::Process::get_id() const {
    return static_cast<size_t>(GetProcessId(handle_.get()));
}

inline void
tml::Process::_launch_exit_wait_impl(
    TML_VALUE_PARAM const Handle child_handle,
    TML_VALUE_PARAM OnExitCallback cb
) {
    const DWORD wait_res = WaitForSingleObject(child_handle.get(), INFINITE);
    cb(wait_res == WAIT_FAILED ? ExitCode{0, ExitCode::Type::Unknown} : child_handle.get_exit_code());
}

inline void
tml::Process::_launch_pipe_aligned_read_impl(
    TML_VALUE_PARAM const OutputDevice::Value pipe_end,
    TML_VALUE_PARAM AlignedBufferCallback cb,
    size_t buffer_length
) {
    if(buffer_length == 0) {
        buffer_length = 200;
    }

    DWORD bytes_read = 0;
    const AlignedFlatBuffer buffer(buffer_length);

    while(ReadFile(
        pipe_end,              // Windows file handle (in this case a pipe end)
        buffer.data(),         // Pointer to receive read bytes.
        buffer.size(),         // Size of the buffer.
        &bytes_read,           // Pointer to a DWORD that recieves the number of bytes read.
        nullptr                // Optional pointer to an OVERLAPPED structure for async IO.
    ) && bytes_read > 0) {     // I think this makes sense?
        cb(buffer);
        memset(buffer.data(), static_cast<uint8_t>(0), buffer.size());
    }
}

inline void
tml::Process::_launch_pipe_dyn_read_impl(
    TML_VALUE_PARAM const OutputDevice::Value pipe_end,
    TML_VALUE_PARAM DynamicBufferCallback cb,
    size_t buffer_length
) {
    if(buffer_length == 0) {
        buffer_length = 200;
    }

    DWORD bytes_read = 0;
    std::vector<uint8_t> buffer(buffer_length);
    while(ReadFile(
        pipe_end,
        buffer.data(),
        buffer.size(),
        &bytes_read,
        nullptr
    ) && bytes_read > 0) {
        cb(buffer);
        std::ranges::fill(buffer, static_cast<uint8_t>('\0'));
    }
}

inline tml::Process&
tml::Process::launch() {
    auto        hredirect   = OutputDevice::get_invalid_handle_state();
    auto*       ppipe       = std::get_if<OutputDevice::AnonymousPipe>(&output_);
    auto*       pfile       = std::get_if<OutputDevice>(&output_);
    const auto* pdyncb      = std::get_if<DynamicBufferCallback>(&output_callback_);
    const auto* palignedcb  = std::get_if<AlignedBufferCallback>(&output_callback_);
    const auto* pexitcb     = std::get_if<OnExitCallback>(&exit_callback_);

    PROCESS_INFORMATION proc_info = { 0 }; // Stores process information: process and thread handles.
    STARTUPINFOW startup_info     = { 0 }; // Startup info: should include relevant flags.
    NativeString arguments;                // Full argument string to be used as CreateProcess' second parameter.

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Verify arguments because if anything is empty it's possible UB for the heap copy cancer.

    if([this]() -> bool {
        for(const auto& arg : arguments_) {
            if(arg.empty()) return true;
        }
        return name_.empty();
    }()) {
        SetLastError(ERROR_BAD_ARGUMENTS);
        throw TMLException::ProcessLaunchException();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Remove backslashes from paths, convert name + args into a single string.

    auto to_backslashes = [](const NativeChar c) -> NativeChar {
        return c == L'/' ? L'\\' : c;
    };

    std::ranges::transform(working_directory_, working_directory_.begin(), to_backslashes);
    std::ranges::transform(name_, name_.begin(), to_backslashes);

    const NativeString full_args = [&]() -> NativeString {
        NativeString _str = name_;
        for(const auto& arg : arguments_) {
            _str += L' ' + arg;
        }
        return _str;
    }();

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // Redirect console output into a pipe or handle.

    if(ppipe != nullptr) hredirect = ppipe->write_end.value();
    if(pfile != nullptr) hredirect = pfile->value();

    if(!OutputDevice::is_invalid_handle_state(hredirect)) {
        startup_info.dwFlags   |= STARTF_USESTDHANDLES;
        startup_info.hStdError  = hredirect;
        startup_info.hStdOutput = hredirect;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // launch the process.

    /*
     * IMPORTANT:
     * The second argument of CreateProcessW needs to be a pointer to a null terminated
     * wide character string. Microsoft's documentation specifies that CreateProcessW WILL
     * modify the contents of this string. According to cppreference,
     * "modifying the contents of the string returned from the const overload of std::wstring::c_str()
     * has undefined behaviour". For this reason we need to use std::wstring to
     * help with string concatenation, and then copy the string's contents into a new buffer
     * that we can guarantee it is valid to write to. Quite annoying, but necessary here.
     */

    auto* tmp_arg_buff = new wchar_t[full_args.size() + 1];
    tml_defer([tmp_arg_buff] {
        delete[] tmp_arg_buff;
    });

    tmp_arg_buff[full_args.size()] = L'\0';
    memcpy(tmp_arg_buff, full_args.data(), full_args.size());
    startup_info.cb = sizeof(startup_info);

    if(!CreateProcessW(
        nullptr,
        tmp_arg_buff,
        nullptr,
        nullptr,
        TRUE,
        0,
        nullptr,
        working_directory_.c_str(),
        &startup_info,
        &proc_info
    )) {
        throw TMLException::ProcessLaunchException();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////
    // set up callback handlers.

    if(pdyncb != nullptr || palignedcb != nullptr) {
        tml_assert(ppipe != nullptr);
        ppipe->write_end.close();
        ppipe->write_end.invalidate();
    }

    if(pdyncb) { // dynamic buffer (std::vector) cb.
        output_callback_worker_ = std::make_unique<std::thread>(
            _launch_pipe_dyn_read_impl,
            ppipe->read_end.value(),
            *pdyncb,
            callback_buffer_hint_
        );
    }

    else if(palignedcb) { // aligned buffer cb.
        output_callback_worker_ = std::make_unique<std::thread>(
            _launch_pipe_aligned_read_impl,
            pfile->value(),
            *palignedcb,
            callback_buffer_hint_
        );
    }

    if(pexitcb) { // OnExit cb.
        exit_callback_worker_ = std::make_unique<std::thread>(
            _launch_exit_wait_impl,
            Handle(proc_info.hProcess),
            *pexitcb
        );
    }

    handle_ = Handle(proc_info.hProcess);
    CloseHandle(proc_info.hThread);
    return *this;
}

inline
tml::Process::~Process() {
    tml_defer([this] {
        handle_.close();
        if(output_callback_worker_) output_callback_worker_->join();
        if(exit_callback_worker_)   exit_callback_worker_->join();
    });

    if(auto* pfile = std::get_if<OutputDevice>(&output_)) {
        pfile->close();
        pfile->invalidate();
    }

    if(auto* ppipe = std::get_if<OutputDevice::AnonymousPipe>(&output_)) {
        ppipe->read_end  .close();
        ppipe->write_end .close();
        ppipe->read_end  .invalidate();
        ppipe->write_end .invalidate();
    }

    if(Handle::is_invalid_handle_state(handle_)
     || handle_.get_exit_code().type != ExitCode::Type::NotExited) {
        return;
    }
    handle_.kill();
}


#else // OS == POSIX

[[noreturn]] inline void
tml::Process::_posix_child_launch_impl() {
    auto* pipe_ptr    = std::get_if<OutputDevice::AnonymousPipe>(&output_);
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
    auto*       ppipe       = std::get_if<OutputDevice::AnonymousPipe>(&output_);
    const auto* pdyncb      = std::get_if<DynamicBufferCallback>(&output_callback_);
    const auto* palignedcb  = std::get_if<AlignedBufferCallback>(&output_callback_);
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
    ppipe->write_end.invalidate();

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
    TML_VALUE_PARAM AlignedBufferCallback cb,
    size_t buffer_length
) {
    if(buffer_length == 0) {
        buffer_length = 200;
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = pipe_end;
    fds[0].events = POLLIN;

    const AlignedFlatBuffer buffer(buffer_length);
    while(true) {
        if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
            break;
        }

        fds[0].revents = 0;
        if(::read(pipe_end, buffer.data(), buffer.size()) <= 0) {
            break;
        }

        cb(buffer);
    }
}

inline void
tml::Process::_launch_pipe_dyn_read_impl(
    TML_VALUE_PARAM const OutputDevice::Value pipe_end,
    TML_VALUE_PARAM DynamicBufferCallback cb,
    size_t buffer_length
) {
    if(buffer_length == 0) {
        buffer_length = 200;
    }

    pollfd fds[1] = { 0 };
    fds[0].fd     = pipe_end;
    fds[0].events = POLLIN;

    std::vector<uint8_t> buffer(buffer_length);
    while(true) {
        if(::poll(fds, 1, -1) == -1 || !(fds[0].revents & POLLIN)) {
            break;
        }

        fds[0].revents = 0;
        if(::read(pipe_end, buffer.data(), buffer.size()) <= 0) {
            break;
        }

        cb(buffer);
        std::ranges::fill(buffer, static_cast<uint8_t>('\0'));
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

inline size_t
tml::Process::get_id() const {
    return static_cast<size_t>(handle_.get());
}

inline tml::ExitCode
tml::Process::wait() {
    if(posix_cached_exit_code_.type == ExitCode::Type::Unknown) {
        posix_cached_exit_code_ = _posix_blocking_wait_impl(handle_);
    }
    return posix_cached_exit_code_;
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

    if(auto* pfile = std::get_if<OutputDevice>(&output_)) {
        pfile->close();
        pfile->invalidate();
    }

    if(auto* ppipe = std::get_if<OutputDevice::AnonymousPipe>(&output_)) {
        ppipe->read_end  .close();
        ppipe->write_end .close();
        ppipe->read_end  .invalidate();
        ppipe->write_end .invalidate();
    }

    // ReSharper disable once CppTooWideScopeInitStatement
    const auto child_exit = handle_.get_exit_code().type;
    if(Handle::is_invalid_handle_state(handle_) || child_exit != ExitCode::Type::NotExited) {
        return;
    }

    handle_.close();
}

#endif // #if defined(TML_WINDOWS)
#endif //TML_HPP
