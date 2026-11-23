#ifndef DPI_TLS_STREAM_PARSER_H
#define DPI_TLS_STREAM_PARSER_H

#include "stream_types.h"
#include <vector>
#include <string>
#include <optional>

namespace DPI {

class TLSStreamParser {
public:
    // Parse TLS records from reconstructed byte stream and extract metadata
    static TLSStreamMetadata parseStream(const uint8_t* data, size_t len);

    // Helper to convert 16-bit TLS version to human-readable string
    static std::string versionToString(uint16_t version);

private:
    static constexpr uint8_t CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14;
    static constexpr uint8_t CONTENT_TYPE_ALERT              = 0x15;
    static constexpr uint8_t CONTENT_TYPE_HANDSHAKE          = 0x16;
    static constexpr uint8_t CONTENT_TYPE_APPLICATION_DATA   = 0x17;

    static constexpr uint8_t HANDSHAKE_CLIENT_HELLO          = 0x01;
    static constexpr uint8_t HANDSHAKE_SERVER_HELLO          = 0x02;

    static constexpr uint16_t EXTENSION_SNI                = 0x0000;
    static constexpr uint16_t EXTENSION_ALPN               = 0x0010;
    static constexpr uint16_t EXTENSION_SUPPORTED_VERSIONS = 0x002b;

    static uint16_t readUint16BE(const uint8_t* p);
    static uint32_t readUint24BE(const uint8_t* p);

    static bool parseClientHello(const uint8_t* data, size_t len, TLSStreamMetadata& meta);
    static void parseExtensions(const uint8_t* data, size_t len, TLSStreamMetadata& meta);
    static void parseSNIExtension(const uint8_t* data, size_t len, TLSStreamMetadata& meta);
    static void parseALPNExtension(const uint8_t* data, size_t len, TLSStreamMetadata& meta);
    static void parseSupportedVersionsExtension(const uint8_t* data, size_t len, TLSStreamMetadata& meta);
};

} // namespace DPI

#endif // DPI_TLS_STREAM_PARSER_H
