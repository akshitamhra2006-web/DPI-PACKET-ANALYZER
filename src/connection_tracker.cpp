#include "connection_tracker.h"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <mutex>

namespace DPI {

// ============================================================================
// ConnectionTracker Implementation
// ============================================================================

ConnectionTracker::ConnectionTracker(int fp_id, size_t max_connections)
    : fp_id_(fp_id), max_connections_(max_connections) {
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple) {
    FiveTuple canonical = tuple.toCanonical();
    auto it = connections_.find(canonical);
    
    if (it != connections_.end()) {
        // Move to front of LRU list (O(1))
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_it);
        return &it->second.conn;
    }
    
    // Check if we need to evict old connections
    if (connections_.size() >= max_connections_) {
        evictOldest();
    }
    
    // Create new connection using canonical tuple
    Connection conn;
    conn.tuple = canonical;
    conn.state = ConnectionState::NEW;
    conn.first_seen = std::chrono::steady_clock::now();
    conn.last_seen = conn.first_seen;
    
    lru_list_.push_front(canonical);
    auto result = connections_.emplace(canonical, ConnectionNode{std::move(conn), lru_list_.begin()});
    total_seen_++;
    
    return &result.first->second.conn;
}

Connection* ConnectionTracker::getConnection(const FiveTuple& tuple) {
    FiveTuple canonical = tuple.toCanonical();
    auto it = connections_.find(canonical);
    if (it != connections_.end()) {
        // Move to front of LRU list (O(1))
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_it);
        return &it->second.conn;
    }
    
    return nullptr;
}

void ConnectionTracker::updateConnection(Connection* conn, size_t packet_size, bool is_outbound) {
    if (!conn) return;
    
    conn->last_seen = std::chrono::steady_clock::now();
    
    if (is_outbound) {
        conn->packets_out++;
        conn->bytes_out += packet_size;
    } else {
        conn->packets_in++;
        conn->bytes_in += packet_size;
    }
}

void ConnectionTracker::classifyConnection(Connection* conn, AppType app, const std::string& sni) {
    if (!conn) return;
    
    if (conn->state != ConnectionState::CLASSIFIED) {
        conn->app_type = app;
        conn->sni = sni;
        conn->state = ConnectionState::CLASSIFIED;
        classified_count_++;
    }
}

void ConnectionTracker::blockConnection(Connection* conn) {
    if (!conn) return;
    
    conn->state = ConnectionState::BLOCKED;
    conn->action = PacketAction::DROP;
    blocked_count_++;
}

void ConnectionTracker::closeConnection(const FiveTuple& tuple) {
    FiveTuple canonical = tuple.toCanonical();
    auto it = connections_.find(canonical);
    if (it != connections_.end()) {
        it->second.conn.state = ConnectionState::CLOSED;
    }
}

size_t ConnectionTracker::cleanupStale(std::chrono::seconds timeout) {
    auto now = std::chrono::steady_clock::now();
    size_t removed = 0;
    
    for (auto it = connections_.begin(); it != connections_.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.conn.last_seen);
        
        if (age > timeout || it->second.conn.state == ConnectionState::CLOSED) {
            lru_list_.erase(it->second.lru_it);
            it = connections_.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    return removed;
}

std::vector<Connection> ConnectionTracker::getAllConnections() const {
    std::vector<Connection> result;
    result.reserve(connections_.size());
    
    for (const auto& pair : connections_) {
        result.push_back(pair.second.conn);
    }
    
    return result;
}

size_t ConnectionTracker::getActiveCount() const {
    return connections_.size();
}

ConnectionTracker::TrackerStats ConnectionTracker::getStats() const {
    TrackerStats stats;
    stats.active_connections = connections_.size();
    stats.total_connections_seen = total_seen_;
    stats.classified_connections = classified_count_;
    stats.blocked_connections = blocked_count_;
    return stats;
}

void ConnectionTracker::clear() {
    lru_list_.clear();
    connections_.clear();
}

void ConnectionTracker::forEach(std::function<void(const Connection&)> callback) const {
    for (const auto& pair : connections_) {
        callback(pair.second.conn);
    }
}

void ConnectionTracker::evictOldest() {
    if (lru_list_.empty()) return;
    
    // O(1) LRU eviction from back of list
    FiveTuple oldest = lru_list_.back();
    lru_list_.pop_back();
    connections_.erase(oldest);
}

// ============================================================================
// GlobalConnectionTable Implementation
// ============================================================================

GlobalConnectionTable::GlobalConnectionTable(size_t num_fps) {
    trackers_.resize(num_fps, nullptr);
}

void GlobalConnectionTable::registerTracker(int fp_id, ConnectionTracker* tracker) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (fp_id < static_cast<int>(trackers_.size())) {
        trackers_[fp_id] = tracker;
    }
}

GlobalConnectionTable::GlobalStats GlobalConnectionTable::getGlobalStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    
    GlobalStats stats;
    stats.total_active_connections = 0;
    stats.total_connections_seen = 0;
    
    std::unordered_map<std::string, size_t> domain_counts;
    
    for (const auto* tracker : trackers_) {
        if (!tracker) continue;
        
        auto tracker_stats = tracker->getStats();
        stats.total_active_connections += tracker_stats.active_connections;
        stats.total_connections_seen += tracker_stats.total_connections_seen;
        
        // Collect app distribution
        tracker->forEach([&](const Connection& conn) {
            stats.app_distribution[conn.app_type]++;
            if (!conn.sni.empty()) {
                domain_counts[conn.sni]++;
            }
        });
    }
    
    // Get top domains
    std::vector<std::pair<std::string, size_t>> domain_vec(
        domain_counts.begin(), domain_counts.end());
    
    std::sort(domain_vec.begin(), domain_vec.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Take top 20
    size_t count = std::min(domain_vec.size(), static_cast<size_t>(20));
    stats.top_domains.assign(domain_vec.begin(), domain_vec.begin() + count);
    
    return stats;
}

std::string GlobalConnectionTable::generateReport() const {
    auto stats = getGlobalStats();
    
    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║               CONNECTION STATISTICS REPORT                    ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    ss << "║ Active Connections:     " << std::setw(10) << stats.total_active_connections << "                          ║\n";
    ss << "║ Total Connections Seen: " << std::setw(10) << stats.total_connections_seen << "                          ║\n";
    
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║                    APPLICATION BREAKDOWN                      ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    
    // Calculate total for percentages
    size_t total = 0;
    for (const auto& pair : stats.app_distribution) {
        total += pair.second;
    }
    
    // Sort by count
    std::vector<std::pair<AppType, size_t>> sorted_apps(
        stats.app_distribution.begin(), stats.app_distribution.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (const auto& pair : sorted_apps) {
        double pct = total > 0 ? (100.0 * pair.second / total) : 0;
        ss << "║ " << std::setw(20) << std::left << appTypeToString(pair.first)
           << std::setw(10) << std::right << pair.second
           << " (" << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%)           ║\n";
    }
    
    if (!stats.top_domains.empty()) {
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        ss << "║                      TOP DOMAINS                             ║\n";
        ss << "╠══════════════════════════════════════════════════════════════╣\n";
        
        for (const auto& pair : stats.top_domains) {
            std::string domain = pair.first;
            if (domain.length() > 35) {
                domain = domain.substr(0, 32) + "...";
            }
            ss << "║ " << std::setw(40) << std::left << domain
               << std::setw(10) << std::right << pair.second << "           ║\n";
        }
    }
    
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return ss.str();
}

} // namespace DPI
