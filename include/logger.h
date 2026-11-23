#ifndef DPI_LOGGER_H
#define DPI_LOGGER_H

#include <string>
#include <mutex>
#include <iostream>

namespace DPI {

class Logger {
public:
    // Thread-safe console logging
    static void log(const std::string& msg);
    static void logError(const std::string& msg);

private:
    static std::mutex log_mutex_;
};

} // namespace DPI

#endif // DPI_LOGGER_H
