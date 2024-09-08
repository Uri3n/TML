//
// Created by Diago on 2024-09-07.
//

#include <tml.hpp>


#if defined(TML_WINDOWS)
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

#else // OS == UNIX
std::string
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