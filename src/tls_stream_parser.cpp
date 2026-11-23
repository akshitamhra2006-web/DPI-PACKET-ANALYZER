#include "tls_stream_parser.h"
#include <algorithm>
#include <sstream>

namespace DPI {

uint16_t TLSStreamParser::readUint16BE(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

uint32_t TLSStreamParser::readUint24BE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
           p[2];
}

std::string TLSStreamParser::versionToString(uint16_t version) {
    switch (version) {
        case 0x0300: return "SSL 3.0";
        case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1";
        case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3";
        default: {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::setw(4) << std::setfill('0') << version;
            return ss.str();
        }
    }
}

TLSStreamMetadata TLSStreamParser::parseStream(const uint8_t* data, size_t len) {
    TLSStreamMetadata meta;
    if (!data || len < 5) return meta;

    size_t offset = 0;
    while (offset + 5 <= len) {
        uint8_t content_type = data[offset];
        uint16_t version = readUint16BE(data + offset + 1);
        uint16_t record_len = readUint16BE(data + offset + 3);

        if (meta.record_version == 0) {
            meta.record_version = version;
        }

        // Validate basic TLS version (SSL 3.0 through TLS 1.3)
        if (version < 0x0300 || version > 0x0304) {
            break; // Not a valid TLS record header
        }

        offset += 5;
        if (offset + record_len > len) {
            // Incomplete/truncated TLS record
            break;
        }

        const uint8_t* record_payload = data + offset;

        if (content_type == CONTENT_TYPE_HANDSHAKE && record_len >= 4) {
            uint8_t handshake_type = record_payload[0];
            uint32_t handshake_len = readUint24BE(record_payload + 1);

            if (handshake_type == HANDSHAKE_CLIENT_HELLO && 4 + handshake_len <= record_len) {
                parseClientHello(record_payload + 4, handshake_len, meta);
            }
        } else if (content_type == CONTENT_TYPE_APPLICATION_DATA) {
            meta.has_encrypted_data = true;
            meta.encrypted_record_count++;
            meta.encrypted_bytes_count += record_len;
        }

        offset += record_len;
    }

    return meta;
}

bool TLSStreamParser::parseClientHello(const uint8_t* data, size_t len, TLSStreamMetadata& meta) {
    meta.has_client_hello = true;
    if (len < 34) return false;

    // Bytes 0-1: Client version
    meta.client_version = readUint16BE(data);
    size_t offset = 2;

    // Bytes 2-33: Random (32 bytes)
    offset += 32;

    // Session ID
    if (offset >= len) return false;
    uint8_t session_id_len = data[offset++];
    if (offset + session_id_len > len) return false;
    offset += session_id_len;

    // Cipher Suites
    if (offset + 2 > len) return false;
    uint16_t cipher_suites_len = readUint16BE(data + offset);
    offset += 2;
    if (offset + cipher_suites_len > len) return false;

    size_t cipher_count = cipher_suites_len / 2;
    for (size_t i = 0; i < cipher_count && i < 128; ++i) {
        meta.cipher_suites.push_back(readUint16BE(data + offset + i * 2));
    }
    offset += cipher_suites_len;

    // Compression Methods
    if (offset >= len) return false;
    uint8_t comp_methods_len = data[offset++];
    if (offset + comp_methods_len > len) return false;
    offset += comp_methods_len;

    // Extensions
    if (offset + 2 <= len) {
        uint16_t extensions_len = readUint16BE(data + offset);
        offset += 2;
        size_t available_ext_len = std::min(static_cast<size_t>(extensions_len), len - offset);
        parseExtensions(data + offset, available_ext_len, meta);
    }

    // Default fallback supported version if not explicitly set via extension
    if (meta.supported_versions.empty() && meta.client_version != 0) {
        meta.supported_versions.push_back(versionToString(meta.client_version));
    }

    return true;
}

void TLSStreamParser::parseExtensions(const uint8_t* data, size_t len, TLSStreamMetadata& meta) {
    size_t offset = 0;
    while (offset + 4 <= len) {
        uint16_t ext_type = readUint16BE(data + offset);
        uint16_t ext_len = readUint16BE(data + offset + 2);
        offset += 4;

        if (offset + ext_len > len) break;

        const uint8_t* ext_data = data + offset;
        if (ext_type == EXTENSION_SNI) {
            parseSNIExtension(ext_data, ext_len, meta);
        } else if (ext_type == EXTENSION_ALPN) {
            parseALPNExtension(ext_data, ext_len, meta);
        } else if (ext_type == EXTENSION_SUPPORTED_VERSIONS) {
            parseSupportedVersionsExtension(ext_data, ext_len, meta);
        }

        offset += ext_len;
    }
}

void TLSStreamParser::parseSNIExtension(const uint8_t* data, size_t len, TLSStreamMetadata& meta) {
    if (len < 5) return;
    uint16_t list_len = readUint16BE(data);
    if (list_len + 2 > len) return;

    size_t offset = 2;
    while (offset + 3 <= len) {
        uint8_t name_type = data[offset++];
        uint16_t name_len = readUint16BE(data + offset);
        offset += 2;

        if (offset + name_len > len) break;

        if (name_type == 0x00) { // host_name
            meta.sni = std::string(reinterpret_cast<const char*>(data + offset), name_len);
            break;
        }
        offset += name_len;
    }
}

void TLSStreamParser::parseALPNExtension(const uint8_t* data, size_t len, TLSStreamMetadata& meta) {
    if (len < 2) return;
    uint16_t list_len = readUint16BE(data);
    if (list_len + 2 > len) return;

    size_t offset = 2;
    std::string alpn_list;
    while (offset < len) {
        uint8_t proto_len = data[offset++];
        if (offset + proto_len > len) break;

        std::string proto(reinterpret_cast<const char*>(data + offset), proto_len);
        if (!alpn_list.empty()) alpn_list += ",";
        alpn_list += proto;
        offset += proto_len;
    }
    meta.alpn = alpn_list;
}

void TLSStreamParser::parseSupportedVersionsExtension(const uint8_t* data, size_t len, TLSStreamMetadata& meta) {
    if (len < 1) return;
    uint8_t list_len = data[0];
    if (static_cast<size_t>(list_len) + 1 > len) return;

    size_t offset = 1;
    while (offset + 2 <= len && offset < static_cast<size_t>(list_len) + 1) {
        uint16_t ver = readUint16BE(data + offset);
        // Ignore GREASE versions (0x?a?a)
        if ((ver & 0x0f0f) != 0x0a0a) {
            meta.supported_versions.push_back(versionToString(ver));
        }
        offset += 2;
    }
}

} // namespace DPI
