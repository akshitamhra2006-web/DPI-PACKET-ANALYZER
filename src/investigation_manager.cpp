#include "investigation_manager.h"
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace DPI {

static inline uint64_t getCurrentTimeUs() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
}

std::string InvestigationManager::calculateHash(const std::string& content) {
    // 64-bit FNV-1a hash formatted as 16-hex characters
    uint64_t hash = 14695981039346656037ULL;
    for (unsigned char c : content) {
        hash ^= c;
        hash *= 1099511628211ULL;
    }
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << hash;
    return ss.str();
}

std::string InvestigationManager::createInvestigation(const std::string& title,
                                                     const std::string& description,
                                                     InvestigationPriority priority,
                                                     const std::vector<std::string>& tags) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t now = getCurrentTimeUs();

    std::ostringstream ss;
    ss << "INV-" << std::setfill('0') << std::setw(4) << next_inv_id_++;
    std::string id = ss.str();

    InvestigationRecord rec;
    rec.investigation_id = id;
    rec.title = title;
    rec.description = description;
    rec.created_at_us = now;
    rec.updated_at_us = now;
    rec.status = InvestigationStatus::OPEN;
    rec.priority = priority;
    rec.tags = tags;

    investigations_[id] = rec;
    return id;
}

bool InvestigationManager::updateInvestigation(const std::string& id,
                                              const std::string& title,
                                              const std::string& description,
                                              InvestigationStatus status,
                                              InvestigationPriority priority,
                                              const std::vector<std::string>& tags) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(id);
    if (it == investigations_.end()) return false;

    it->second.title = title;
    it->second.description = description;
    it->second.status = status;
    it->second.priority = priority;
    it->second.tags = tags;
    it->second.updated_at_us = getCurrentTimeUs();
    return true;
}

bool InvestigationManager::addNote(const std::string& inv_id,
                                  const std::string& author,
                                  const std::string& content) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    InvestigationNote note;
    std::ostringstream ss;
    ss << "NOTE-" << std::setfill('0') << std::setw(4) << next_note_id_++;
    note.note_id = ss.str();
    note.timestamp_us = getCurrentTimeUs();
    note.author = author;
    note.content = content;

    it->second.notes.push_back(note);
    it->second.updated_at_us = note.timestamp_us;
    return true;
}

std::string InvestigationManager::addEvidence(const std::string& inv_id,
                                             EvidenceType type,
                                             const std::string& source_id,
                                             const std::string& description,
                                             const std::string& raw_content_for_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return "";

    EvidenceReference ev;
    std::ostringstream ss;
    ss << "EV-" << std::setfill('0') << std::setw(4) << next_evidence_id_++;
    ev.evidence_id = ss.str();
    ev.type = type;
    ev.source_id = source_id;
    ev.description = description;
    ev.integrity_hash = calculateHash(raw_content_for_hash.empty() ? (source_id + description) : raw_content_for_hash);
    ev.timestamp_us = getCurrentTimeUs();

    it->second.evidence_list.push_back(ev);
    it->second.updated_at_us = ev.timestamp_us;
    return ev.evidence_id;
}

bool InvestigationManager::removeEvidence(const std::string& inv_id, const std::string& evidence_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    auto& list = it->second.evidence_list;
    auto rem_it = std::remove_if(list.begin(), list.end(), [&](const EvidenceReference& r) {
        return r.evidence_id == evidence_id;
    });

    if (rem_it != list.end()) {
        list.erase(rem_it, list.end());
        it->second.updated_at_us = getCurrentTimeUs();
        return true;
    }
    return false;
}

bool InvestigationManager::linkIncident(const std::string& inv_id, const std::string& incident_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    if (std::find(it->second.related_incidents.begin(), it->second.related_incidents.end(), incident_id) ==
        it->second.related_incidents.end()) {
        it->second.related_incidents.push_back(incident_id);
        it->second.updated_at_us = getCurrentTimeUs();
    }
    return true;
}

bool InvestigationManager::linkDetection(const std::string& inv_id, const std::string& detection_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    if (std::find(it->second.related_detections.begin(), it->second.related_detections.end(), detection_id) ==
        it->second.related_detections.end()) {
        it->second.related_detections.push_back(detection_id);
        it->second.updated_at_us = getCurrentTimeUs();
    }
    return true;
}

bool InvestigationManager::linkFlow(const std::string& inv_id, uint64_t flow_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    if (std::find(it->second.related_flows.begin(), it->second.related_flows.end(), flow_id) ==
        it->second.related_flows.end()) {
        it->second.related_flows.push_back(flow_id);
        it->second.updated_at_us = getCurrentTimeUs();
    }
    return true;
}

bool InvestigationManager::linkEndpoint(const std::string& inv_id, const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    if (std::find(it->second.related_endpoints.begin(), it->second.related_endpoints.end(), ip) ==
        it->second.related_endpoints.end()) {
        it->second.related_endpoints.push_back(ip);
        it->second.updated_at_us = getCurrentTimeUs();
    }
    return true;
}

bool InvestigationManager::linkIOC(const std::string& inv_id, const std::string& ioc_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    if (std::find(it->second.related_iocs.begin(), it->second.related_iocs.end(), ioc_id) ==
        it->second.related_iocs.end()) {
        it->second.related_iocs.push_back(ioc_id);
        it->second.updated_at_us = getCurrentTimeUs();
    }
    return true;
}

bool InvestigationManager::setStatus(const std::string& inv_id, InvestigationStatus status) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(inv_id);
    if (it == investigations_.end()) return false;

    it->second.status = status;
    it->second.updated_at_us = getCurrentTimeUs();
    return true;
}

const InvestigationRecord* InvestigationManager::getInvestigation(const std::string& id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(id);
    if (it != investigations_.end()) return &it->second;
    return nullptr;
}

InvestigationRecord* InvestigationManager::getInvestigationMutable(const std::string& id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = investigations_.find(id);
    if (it != investigations_.end()) return &it->second;
    return nullptr;
}

std::vector<InvestigationRecord> InvestigationManager::getAllInvestigations() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<InvestigationRecord> vec;
    vec.reserve(investigations_.size());
    for (const auto& p : investigations_) {
        vec.push_back(p.second);
    }
    std::sort(vec.begin(), vec.end(), [](const InvestigationRecord& a, const InvestigationRecord& b) {
        return a.created_at_us > b.created_at_us;
    });
    return vec;
}

size_t InvestigationManager::getInvestigationCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return investigations_.size();
}

std::string InvestigationManager::toJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream ss;
    ss << "[\n";
    bool first = true;
    for (const auto& p : investigations_) {
        if (!first) ss << ",\n";
        ss << "  " << p.second.toJson();
        first = false;
    }
    ss << "\n]\n";
    return ss.str();
}

bool InvestigationManager::saveToFile(const std::string& filepath) const {
    std::string content = toJson();
    std::string tmp_path = filepath + ".tmp";
    std::ofstream ofs(tmp_path);
    if (!ofs.is_open()) return false;
    ofs << content;
    ofs.close();
    return std::rename(tmp_path.c_str(), filepath.c_str()) == 0;
}

bool InvestigationManager::loadFromFile(const std::string& filepath) {
    std::ifstream ifs(filepath);
    if (!ifs.is_open()) return false;
    // Basic file existence and read verification
    std::string content((std::istreambuf_iterator<char>(ifs)),
                         std::istreambuf_iterator<char>());
    ifs.close();
    return !content.empty();
}

} // namespace DPI
