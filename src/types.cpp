#include "types.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace DPI {

std::string FiveTuple::toString() const {
    std::ostringstream ss;
    
    // Format IP addresses
    auto formatIP = [](uint32_t ip) {
        std::ostringstream s;
        s << ((ip >> 0) & 0xFF) << "."
          << ((ip >> 8) & 0xFF) << "."
          << ((ip >> 16) & 0xFF) << "."
          << ((ip >> 24) & 0xFF);
        return s.str();
    };
    
    ss << formatIP(src_ip) << ":" << src_port
       << " -> "
       << formatIP(dst_ip) << ":" << dst_port
       << " (" << (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "?") << ")";
    
    return ss.str();
}

std::string appTypeToString(AppType type) {
    switch (type) {
        case AppType::UNKNOWN:    return "Unknown";
        case AppType::HTTP:       return "HTTP";
        case AppType::HTTPS:      return "HTTPS";
        case AppType::DNS:        return "DNS";
        case AppType::TLS:        return "TLS";
        case AppType::QUIC:       return "QUIC";
        case AppType::GOOGLE:     return "Google";
        case AppType::FACEBOOK:   return "Facebook";
        case AppType::YOUTUBE:    return "YouTube";
        case AppType::TWITTER:    return "Twitter/X";
        case AppType::INSTAGRAM:  return "Instagram";
        case AppType::NETFLIX:    return "Netflix";
        case AppType::AMAZON:     return "Amazon";
        case AppType::MICROSOFT:  return "Microsoft";
        case AppType::APPLE:      return "Apple";
        case AppType::WHATSAPP:   return "WhatsApp";
        case AppType::TELEGRAM:   return "Telegram";
        case AppType::TIKTOK:     return "TikTok";
        case AppType::SPOTIFY:    return "Spotify";
        case AppType::ZOOM:       return "Zoom";
        case AppType::DISCORD:    return "Discord";
        case AppType::GITHUB:     return "GitHub";
        case AppType::CLOUDFLARE: return "Cloudflare";
        default:                  return "Unknown";
    }
}

namespace {

// Helper for exact hostname or anchored subdomain matching
// e.g., "sub.example.com" matches "example.com"
// "example.com" matches "example.com"
// "notexample.com" DOES NOT match "example.com"
// "netflix.com" DOES NOT match "x.com"
// "microsoft.com" DOES NOT match "t.co"
bool domainMatches(const std::string& host, const std::string& target) {
    if (host.length() < target.length()) return false;
    if (host == target) return true;
    if (host.length() > target.length() && host[host.length() - target.length() - 1] == '.') {
        return host.compare(host.length() - target.length(), target.length(), target) == 0;
    }
    return false;
}

bool domainMatchesAny(const std::string& host, const std::vector<std::string>& targets) {
    for (const auto& target : targets) {
        if (domainMatches(host, target)) {
            return true;
        }
    }
    return false;
}

} // anonymous namespace

// Map SNI/domain to application type
AppType sniToAppType(const std::string& sni, AppType fallback) {
    if (sni.empty()) return AppType::UNKNOWN;
    
    // Convert to lowercase for matching
    std::string lower_sni = sni;
    std::transform(lower_sni.begin(), lower_sni.end(), lower_sni.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    
    // Strip trailing dot if present (FQDN)
    if (!lower_sni.empty() && lower_sni.back() == '.') {
        lower_sni.pop_back();
    }

    // 1. YouTube (checked before Google so yt3.ggpht.com matches YouTube)
    if (domainMatchesAny(lower_sni, {
            "youtube.com", "ytimg.com", "youtu.be", "yt3.ggpht.com", "youtube-nocookie.com"
        })) {
        return AppType::YOUTUBE;
    }

    // 2. Google
    if (domainMatchesAny(lower_sni, {
            "google.com", "gstatic.com", "googleapis.com", "ggpht.com",
            "gvt1.com", "1e100.net", "googleusercontent.com", "googlevideo.com"
        })) {
        return AppType::GOOGLE;
    }

    // 3. Facebook / Meta
    if (domainMatchesAny(lower_sni, {
            "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "meta.com", "fb.me"
        })) {
        return AppType::FACEBOOK;
    }

    // 4. Instagram
    if (domainMatchesAny(lower_sni, {
            "instagram.com", "cdninstagram.com"
        })) {
        return AppType::INSTAGRAM;
    }

    // 5. WhatsApp
    if (domainMatchesAny(lower_sni, {
            "whatsapp.com", "whatsapp.net", "wa.me"
        })) {
        return AppType::WHATSAPP;
    }

    // 6. Twitter / X (strictly anchored to prevent netflix.com or microsoft.com collisions)
    if (domainMatchesAny(lower_sni, {
            "twitter.com", "twimg.com", "x.com", "t.co"
        })) {
        return AppType::TWITTER;
    }

    // 7. Netflix
    if (domainMatchesAny(lower_sni, {
            "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com"
        })) {
        return AppType::NETFLIX;
    }

    // 8. Amazon
    if (domainMatchesAny(lower_sni, {
            "amazon.com", "amazonaws.com", "cloudfront.net", "aws.amazon.com", "media-amazon.com"
        })) {
        return AppType::AMAZON;
    }

    // 9. Microsoft
    if (domainMatchesAny(lower_sni, {
            "microsoft.com", "msn.com", "office.com", "azure.com", "live.com",
            "outlook.com", "bing.com", "office365.com", "microsoftonline.com"
        })) {
        return AppType::MICROSOFT;
    }

    // 10. Apple
    if (domainMatchesAny(lower_sni, {
            "apple.com", "icloud.com", "mzstatic.com", "itunes.com", "aaplimg.com"
        })) {
        return AppType::APPLE;
    }

    // 11. Telegram
    if (domainMatchesAny(lower_sni, {
            "telegram.org", "t.me", "telegram.me"
        })) {
        return AppType::TELEGRAM;
    }

    // 12. TikTok
    if (domainMatchesAny(lower_sni, {
            "tiktok.com", "tiktokcdn.com", "musical.ly", "byteoversea.com", "bytedance.com"
        })) {
        return AppType::TIKTOK;
    }

    // 13. Spotify
    if (domainMatchesAny(lower_sni, {
            "spotify.com", "scdn.co", "spoti.fi"
        })) {
        return AppType::SPOTIFY;
    }

    // 14. Zoom
    if (domainMatchesAny(lower_sni, {
            "zoom.us", "zoom.com"
        })) {
        return AppType::ZOOM;
    }

    // 15. Discord
    if (domainMatchesAny(lower_sni, {
            "discord.com", "discordapp.com", "discord.gg", "discordapp.net"
        })) {
        return AppType::DISCORD;
    }

    // 16. GitHub
    if (domainMatchesAny(lower_sni, {
            "github.com", "githubusercontent.com", "github.io"
        })) {
        return AppType::GITHUB;
    }

    // 17. Cloudflare
    if (domainMatchesAny(lower_sni, {
            "cloudflare.com", "cloudflare.net"
        })) {
        return AppType::CLOUDFLARE;
    }

    // If domain is present but unrecognized, return caller-provided fallback (HTTP or HTTPS)
    return fallback;
}

} // namespace DPI
