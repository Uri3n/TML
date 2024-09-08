//
// Created by Diago on 2024-09-07.
//

#include <tml.hpp>

tml::TMLException::Type
tml::TMLException::type() const noexcept {
    return type_;
}

const char*
tml::TMLException::what() const noexcept {
    return what_.c_str();
}

tml::TMLException
tml::TMLException::ProcessLaunchException() {
    return TMLException(last_system_error(), Type::ProcessLaunchException);
}

tml::TMLException
tml::TMLException::ProcessTerminationException() {
    return TMLException(last_system_error(), Type::ProcessTerminationException);
}

tml::TMLException
tml::TMLException::OutputDeviceReadException() {
    return TMLException(last_system_error(), Type::OutputDeviceReadException);
}

tml::TMLException
tml::TMLException::OutputDeviceCreationException() {
    return TMLException(last_system_error(), Type::OutputDeviceCreationException);
}
