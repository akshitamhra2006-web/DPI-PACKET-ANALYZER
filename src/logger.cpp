#include "logger.h"

namespace DPI {

std::mutex Logger::log_mutex_;

void Logger::log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::cout << msg << std::endl;
}

void Logger::logError(const std::string& msg) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::cerr << msg << std::endl;
}

} // namespace DPI
