#ifndef DPI_HTTP_STREAM_PARSER_H
#define DPI_HTTP_STREAM_PARSER_H

#include "stream_types.h"
#include <vector>
#include <string>
#include <optional>

namespace DPI {

class HTTPStreamParser {
public:
    // Parse all HTTP/1.x messages (requests or responses) present in the reassembled byte stream
    static std::vector<HTTPMessage> parseStream(const uint8_t* data, size_t len, size_t max_messages = 50);

    // Try to parse a single HTTP message starting at offset
    // Returns std::nullopt if not an HTTP message or header incomplete
    // Updates bytes_consumed to advance stream offset
    static std::optional<HTTPMessage> parseMessage(const uint8_t* data, size_t len, size_t& bytes_consumed);

private:
    static constexpr size_t MAX_HEADER_SIZE = 16384; // 16 KB max header length
    static constexpr size_t MAX_URI_LENGTH = 4096;   // 4 KB max URI length

    static std::string trim(const std::string& str);
    static std::string toLower(const std::string& str);
    static bool parseRequestLine(const std::string& line, HTTPMessage& msg);
    static bool parseStatusLine(const std::string& line, HTTPMessage& msg);
    static void parseHeaders(const std::string& header_block, HTTPMessage& msg);
    static size_t parseChunkedBodyLength(const uint8_t* data, size_t len);
};

} // namespace DPI

#endif // DPI_HTTP_STREAM_PARSER_H
