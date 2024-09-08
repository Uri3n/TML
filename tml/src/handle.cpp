//
// Created by Diago on 2024-09-07.
//

#include <tml.hpp>
#include <tml_internal.hpp>


tml::Handle::~Handle() {
    if(!is_invalid_handle_state(value_)) {
        close();
    }
}

#if defined(TML_WINDOWS)
tml::Handle::Value
tml::Handle::get_invalid_handle_state() {
    return nullptr;
}

void
tml::Handle::kill() {
    if(!::TerminateProcess(value_, 0)) {
        throw TMLException(last_system_error(), TMLException::Type::ProcessTerminationException);
    }
}

void
tml::Handle::close() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    if(!CloseHandle(value_)) {
        throw TMLException(last_system_error(), TMLException::Type::ProcessTerminationException);
    }
}

bool
tml::Handle::is_invalid_handle_state(const Value value) {
    return value == nullptr || value == INVALID_HANDLE_VALUE;
}

#else // OS == POSIX
tml::Handle::Value
tml::Handle::get_invalid_handle_state() {
    return -1;
}

void
tml::Handle::kill() {
    if(::kill(value_, SIGTERM) == -1) {
        throw TMLException::ProcessTerminationException();
    }
}

tml::Handle::Value
tml::Handle::get() {
    return value_;
}

tml::ExitCode
tml::Handle::get_exit_code() noexcept {
    int status         = 0;
    const pid_t result = ::waitpid(value_, &status, WNOHANG);

    if(result == -1) {
        throw TMLException(last_system_error(), TMLException::Type::None);
    }

    if(result == 0) {
        return ExitCode(0, ExitCode::Type::NotExited);
    }

    if(result == value_) {
        if(WIFEXITED(status)) {
            return ExitCode(WEXITSTATUS(status), ExitCode::Type::Normal);
        }
        if(WIFSIGNALED(status)) {
            return ExitCode(WTERMSIG(status), ExitCode::Type::FromSignal);
        }
        if(WIFSTOPPED(status)) {
            return ExitCode(WSTOPSIG(status), ExitCode::Type::FromSignal);
        }
        return ExitCode(-1, ExitCode::Type::Unknown);
    }

    tml_unreachable;
}

bool
tml::Handle::is_invalid_handle_state(const Value value) {
    return value == get_invalid_handle_state();
}

bool
tml::Handle::is_invalid_handle_state(const Handle &handle) {
    return is_invalid_handle_state(handle.value_);
}

void
tml::Handle::close() {
    if(is_invalid_handle_state(value_)) {
        return;
    }
    kill(); // no notion of "closing" a process on posix systems.
}

#endif // #if defined(TML_WINDOWS)
