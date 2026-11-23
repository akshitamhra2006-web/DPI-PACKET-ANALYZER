#include "http_stream_parser.h"
#include <algorithm>
#include <sstream>
#include <cstring>
#include <cctype>

namespace DPI {

std::string HTTPStreamParser::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

std::string HTTPStreamParser::toLower(const std::string& str) {
    std::string out = str;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return std::tolower(c);
    });
    return out;
}

bool HTTPStreamParser::parseRequestLine(const std::string& line, HTTPMessage& msg) {
    std::istringstream iss(line);
    std::string method, uri, version;
    if (!(iss >> method >> uri >> version)) {
        return false;
    }

    // Validate standard HTTP methods
    static const char* valid_methods[] = {
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"
    };
    bool valid = false;
    for (const char* vm : valid_methods) {
        if (method == vm) {
            valid = true;
            break;
        }
    }
    if (!valid) return false;

    if (version.rfind("HTTP/", 0) != 0) {
        return false;
    }

    if (uri.size() > MAX_URI_LENGTH) {
        uri = uri.substr(0, MAX_URI_LENGTH);
    }

    msg.is_request = true;
    msg.method = method;
    msg.uri = uri;
    msg.version = version;
    return true;
}

bool HTTPStreamParser::parseStatusLine(const std::string& line, HTTPMessage& msg) {
    if (line.rfind("HTTP/", 0) != 0) {
        return false;
    }

    std::istringstream iss(line);
    std::string version;
    int status_code = 0;
    if (!(iss >> version >> status_code)) {
        return false;
    }

    std::string reason_phrase;
    std::getline(iss, reason_phrase);
    reason_phrase = trim(reason_phrase);

    msg.is_request = false;
    msg.version = version;
    msg.status_code = status_code;
    msg.reason_phrase = reason_phrase;
    return true;
}

void HTTPStreamParser::parseHeaders(const std::string& header_block, HTTPMessage& msg) {
    std::istringstream stream(header_block);
    std::string line;

    // Skip the first line (already parsed as request or status line)
    std::getline(stream, line);

    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) continue;

        size_t colon = line.find(':');
        if (colon == std::string::npos) continue;

        std::string key = trim(line.substr(0, colon));
        std::string val = trim(line.substr(colon + 1));
        std::string lower_key = toLower(key);

        msg.headers[key] = val;

        if (lower_key == "host") {
            msg.host = val;
            size_t c = msg.host.find(':');
            if (c != std::string::npos) msg.host = msg.host.substr(0, c);
        } else if (lower_key == "user-agent") {
            msg.user_agent = val;
        } else if (lower_key == "content-type") {
            msg.content_type = val;
        } else if (lower_key == "content-length") {
            try {
                msg.content_length = std::stoll(val);
            } catch (...) {
                msg.content_length = -1;
            }
        } else if (lower_key == "transfer-encoding") {
            if (toLower(val).find("chunked") != std::string::npos) {
                msg.is_chunked = true;
            }
        }
    }
}

size_t HTTPStreamParser::parseChunkedBodyLength(const uint8_t* data, size_t len) {
    size_t offset = 0;
    while (offset < len) {
        // Find chunk size line ending with CRLF
        const uint8_t* crlf = reinterpret_cast<const uint8_t*>(std::memchr(data + offset, '\r', len - offset));
        if (!crlf || crlf + 1 >= data + len || *(crlf + 1) != '\n') {
            break; // Incomplete chunk header
        }

        size_t hex_len = crlf - (data + offset);
        if (hex_len == 0 || hex_len > 16) break;

        std::string hex_str(reinterpret_cast<const char*>(data + offset), hex_len);
        // Strip chunk extensions if any (;ext)
        size_t semi = hex_str.find(';');
        if (semi != std::string::npos) hex_str = hex_str.substr(0, semi);

        size_t chunk_size = 0;
        try {
            chunk_size = std::stoul(hex_str, nullptr, 16);
        } catch (...) {
            break;
        }

        offset = (crlf + 2 - data); // Advance past chunk size line

        if (chunk_size == 0) {
            // Last chunk, skip trailing CRLF (or trailers)
            if (offset + 2 <= len && data[offset] == '\r' && data[offset + 1] == '\n') {
                offset += 2;
            }
            return offset;
        }

        // Advance past chunk payload + CRLF
        offset += chunk_size;
        if (offset + 2 <= len && data[offset] == '\r' && data[offset + 1] == '\n') {
            offset += 2;
        } else {
            break; // Truncated chunk
        }
    }
    return 0; // Incomplete
}

std::optional<HTTPMessage> HTTPStreamParser::parseMessage(const uint8_t* data, size_t len, size_t& bytes_consumed) {
    bytes_consumed = 0;
    if (!data || len < 10) return std::nullopt;

    // Find end of header marked by "\r\n\r\n" or "\n\n"
    size_t header_end = 0;
    size_t delim_len = 0;
    size_t search_limit = std::min(len, MAX_HEADER_SIZE);

    for (size_t i = 0; i + 3 < search_limit; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
            header_end = i;
            delim_len = 4;
            break;
        }
        if (data[i] == '\n' && data[i + 1] == '\n') {
            header_end = i;
            delim_len = 2;
            break;
        }
    }

    if (delim_len == 0) {
        return std::nullopt; // Headers not complete yet
    }

    std::string header_block(reinterpret_cast<const char*>(data), header_end);
    std::string first_line;
    size_t fl_end = header_block.find_first_of("\r\n");
    if (fl_end != std::string::npos) {
        first_line = header_block.substr(0, fl_end);
    } else {
        first_line = header_block;
    }

    HTTPMessage msg;
    bool parsed_fl = false;
    if (first_line.rfind("HTTP/", 0) == 0) {
        parsed_fl = parseStatusLine(first_line, msg);
    } else {
        parsed_fl = parseRequestLine(first_line, msg);
    }

    if (!parsed_fl) {
        return std::nullopt;
    }

    parseHeaders(header_block, msg);

    size_t total_header_consumed = header_end + delim_len;
    size_t remaining_len = len - total_header_consumed;
    const uint8_t* body_data = data + total_header_consumed;

    if (msg.is_chunked) {
        size_t chunk_body_len = parseChunkedBodyLength(body_data, remaining_len);
        if (chunk_body_len > 0) {
            msg.is_complete = true;
            msg.body_bytes_seen = chunk_body_len;
            bytes_consumed = total_header_consumed + chunk_body_len;
        } else {
            msg.is_complete = false;
            msg.body_bytes_seen = remaining_len;
            bytes_consumed = total_header_consumed;
        }
    } else if (msg.content_length >= 0) {
        size_t expected_body = static_cast<size_t>(msg.content_length);
        if (remaining_len >= expected_body) {
            msg.is_complete = true;
            msg.body_bytes_seen = expected_body;
            bytes_consumed = total_header_consumed + expected_body;
        } else {
            msg.is_complete = false;
            msg.body_bytes_seen = remaining_len;
            bytes_consumed = total_header_consumed;
        }
    } else {
        // No body expected for standard GET/HEAD or 204/304
        if (msg.method == "GET" || msg.method == "HEAD" || msg.status_code == 204 || msg.status_code == 304) {
            msg.is_complete = true;
            msg.body_bytes_seen = 0;
            bytes_consumed = total_header_consumed;
        } else {
            // Body extends until stream closes
            msg.is_complete = false;
            msg.body_bytes_seen = remaining_len;
            bytes_consumed = total_header_consumed;
        }
    }

    return msg;
}

std::vector<HTTPMessage> HTTPStreamParser::parseStream(const uint8_t* data, size_t len, size_t max_messages) {
    std::vector<HTTPMessage> messages;
    size_t offset = 0;

    while (offset < len && messages.size() < max_messages) {
        size_t consumed = 0;
        auto msg = parseMessage(data + offset, len - offset, consumed);
        if (!msg) {
            break;
        }
        messages.push_back(*msg);
        if (consumed == 0 || !msg->is_complete) {
            // Cannot advance further until more body data or stream completes
            break;
        }
        offset += consumed;
    }

    return messages;
}

} // namespace DPI
