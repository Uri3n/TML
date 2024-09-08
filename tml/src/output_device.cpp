//
// Created by Diago on 2024-09-07.
//

#include <tml.hpp>
#include <algorithm>


tml::OutputDevice
tml::OutputDevice::create(const Value val, const Type type) {
    OutputDevice device;
    device.value_ = val;
    device.type_  = type;
    return device;
}


#if defined(TML_WINDOWS)
tml::OutputDevice::Value
tml::OutputDevice::get_invalid_handle_state() {
    return nullptr;
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
        nullptr                              // Optional file handle to a template file.
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
tml::OutputDevice::Value
tml::OutputDevice::get_invalid_handle_state() {
    return -1;
}

bool
tml::OutputDevice::is_invalid_handle_state(const Value value) {
    return value == get_invalid_handle_state();
}

tml::OutputDevice
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

tml::OutputDevice::Pipe
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
auto tml::OutputDevice::read() -> std::array<uint8_t, out_size> {
    std::array<uint8_t, out_size> out;
    std::fill(out.begin(), out.end(), '\0');

    if(::read(value_, out.data(), out.size()) == -1) {
        throw TMLException::OutputDeviceReadException();
    }
    return out;
}

template<size_t out_size>
auto tml::OutputDevice::read_into(std::array<uint8_t, out_size>& out) -> void {
    if(::read(value_, out.data(), out.size()) == -1) {
        throw TMLException::OutputDeviceReadException();
    }
}

#endif
