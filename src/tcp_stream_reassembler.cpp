#include "tcp_stream_reassembler.h"
#include "http_stream_parser.h"
#include "tls_stream_parser.h"
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace DPI {

// ============================================================================
// TCPHalfStream Implementation
// ============================================================================

TCPHalfStream::TCPHalfStream(const StreamReassemblyConfig& config)
    : config_(config) {
}

bool TCPHalfStream::processSegment(uint32_t seq, uint32_t ack, uint8_t flags,
                                   const uint8_t* payload, size_t len,
                                   uint64_t timestamp_us) {
    (void)ack;
    (void)timestamp_us;
    stats_.segments_received++;

    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;

    if (flags & RST) {
        stats_.rst_seen = true;
    }

    uint32_t payload_seq = seq;
    size_t payload_len = len;
    const uint8_t* payload_data = payload;

    // Handle SYN packet
    if (flags & SYN) {
        stats_.syn_seen = true;
        stats_.initial_seq = seq;
        stats_.base_seq = seq + 1; // SYN consumes 1 sequence number
        stats_.next_expected_seq = stats_.base_seq;
        initialized_ = true;

        // If SYN carries data (e.g. TCP Fast Open), data starts at seq + 1
        payload_seq = seq + 1;
    } else if (!initialized_) {
        // Mid-stream or asymmetric capture start: initialize sequence space from first seen segment
        stats_.initial_seq = seq;
        stats_.base_seq = seq;
        stats_.next_expected_seq = seq;
        initialized_ = true;
    }

    // Handle FIN packet
    if (flags & FIN) {
        stats_.fin_seen = true;
        // FIN is placed at the end of the payload
        fin_seq_ = payload_seq + static_cast<uint32_t>(payload_len);
        stats_.fin_seq = fin_seq_;
    }

    // Check completeness if FIN was already seen and no payload in this packet
    if (payload_len == 0) {
        if (stats_.fin_seen && seq_gte(stats_.next_expected_seq, fin_seq_)) {
            stats_.is_complete = true;
        }
        return false;
    }

    uint32_t seg_start = payload_seq;
    uint32_t seg_end = seg_start + static_cast<uint32_t>(payload_len);

    // Sanity check: discard segments with ridiculous forward sequence jumps (> 1 GB window)
    if (seq_gt(seg_start, stats_.next_expected_seq) &&
        (seg_start - stats_.next_expected_seq > 0x3FFFFFFF)) {
        return false;
    }

    // 1. Pure Retransmission: segment ends before or at next_expected_seq
    if (seq_lte(seg_end, stats_.next_expected_seq)) {
        stats_.retrans_count++;
        checkConflict(seg_start, payload_data, payload_len);
        return false;
    }

    // 2. Overlapping In-Order: starts before next_expected_seq but ends after it
    if (seq_lt(seg_start, stats_.next_expected_seq)) {
        stats_.overlap_count++;
        
        // Check conflicting bytes in overlapping prefix
        checkConflict(seg_start, payload_data, payload_len);

        // Trim prefix
        uint32_t trim_len = stats_.next_expected_seq - seg_start;
        const uint8_t* accepted_data = payload_data + trim_len;
        size_t accepted_len = payload_len - trim_len;

        // Enforce per-stream buffered memory limit
        if (reassembled_data_.size() + accepted_len > config_.max_buffered_bytes_per_stream) {
            size_t allowed = config_.max_buffered_bytes_per_stream > reassembled_data_.size() ?
                             config_.max_buffered_bytes_per_stream - reassembled_data_.size() : 0;
            if (allowed == 0) return false;
            accepted_len = allowed;
        }

        reassembled_data_.insert(reassembled_data_.end(), accepted_data, accepted_data + accepted_len);
        stats_.bytes_reassembled += accepted_len;
        stats_.next_expected_seq = seg_end;

        drainOutOfOrder();
        
        if (stats_.fin_seen && seq_gte(stats_.next_expected_seq, fin_seq_)) {
            stats_.is_complete = true;
        }
        return true;
    }

    // 3. Exact In-Order: starts exactly at next_expected_seq
    if (seg_start == stats_.next_expected_seq) {
        size_t accepted_len = payload_len;
        if (reassembled_data_.size() + accepted_len > config_.max_buffered_bytes_per_stream) {
            size_t allowed = config_.max_buffered_bytes_per_stream > reassembled_data_.size() ?
                             config_.max_buffered_bytes_per_stream - reassembled_data_.size() : 0;
            if (allowed == 0) return false;
            accepted_len = allowed;
        }

        reassembled_data_.insert(reassembled_data_.end(), payload_data, payload_data + accepted_len);
        stats_.bytes_reassembled += accepted_len;
        stats_.next_expected_seq = seg_end;

        drainOutOfOrder();

        if (stats_.fin_seen && seq_gte(stats_.next_expected_seq, fin_seq_)) {
            stats_.is_complete = true;
        }
        return true;
    }

    // 4. Out-of-Order: starts after next_expected_seq (gap in stream)
    stats_.out_of_order_count++;
    stats_.gap_count++;

    // Check memory limits for out-of-order queue
    if (buffered_bytes_ + payload_len > config_.max_buffered_bytes_per_stream ||
        out_of_order_segments_.size() >= config_.max_segments_per_stream) {
        return false; // Queue full, drop segment
    }

    // Buffer segment
    TCPSegment segment;
    segment.seq = seg_start;
    segment.ack = ack;
    segment.flags = flags;
    segment.payload.assign(payload_data, payload_data + payload_len);
    segment.timestamp_us = timestamp_us;

    buffered_bytes_ += payload_len;
    out_of_order_segments_[seg_start] = std::move(segment);

    return false;
}

bool TCPHalfStream::drainOutOfOrder() {
    bool drained_any = false;

    while (!out_of_order_segments_.empty()) {
        auto it = out_of_order_segments_.begin();
        uint32_t seg_start = it->first;
        size_t seg_len = it->second.length();
        uint32_t seg_end = seg_start + static_cast<uint32_t>(seg_len);

        // Entire segment already covered
        if (seq_lte(seg_end, stats_.next_expected_seq)) {
            buffered_bytes_ -= seg_len;
            out_of_order_segments_.erase(it);
            continue;
        }

        // Segment connects with next_expected_seq
        if (seq_lte(seg_start, stats_.next_expected_seq)) {
            uint32_t trim_len = stats_.next_expected_seq - seg_start;
            const uint8_t* p = it->second.payload.data() + trim_len;
            size_t add_len = seg_len - trim_len;

            if (reassembled_data_.size() + add_len <= config_.max_buffered_bytes_per_stream) {
                reassembled_data_.insert(reassembled_data_.end(), p, p + add_len);
                stats_.bytes_reassembled += add_len;
            }

            stats_.next_expected_seq = seg_end;
            buffered_bytes_ -= seg_len;
            out_of_order_segments_.erase(it);
            drained_any = true;
        } else {
            // Gap remains
            break;
        }
    }

    return drained_any;
}

bool TCPHalfStream::checkConflict(uint32_t seq, const uint8_t* payload, size_t len) {
    if (reassembled_data_.empty() || len == 0) return false;

    uint32_t overlap_start = seq;
    uint32_t overlap_end = std::min(seq + static_cast<uint32_t>(len), stats_.next_expected_seq);
    if (seq_gte(overlap_start, overlap_end)) return false;

    // Check if overlap_start is within our reassembled_data_ buffer
    uint32_t stream_buf_start = stats_.next_expected_seq - static_cast<uint32_t>(reassembled_data_.size());
    if (seq_lt(overlap_start, stream_buf_start)) {
        overlap_start = stream_buf_start; // Only check portion still in buffer
    }

    if (seq_gte(overlap_start, overlap_end)) return false;

    size_t payload_offset = overlap_start - seq;
    size_t buf_offset = overlap_start - stream_buf_start;
    size_t compare_len = overlap_end - overlap_start;

    if (payload_offset + compare_len <= len && buf_offset + compare_len <= reassembled_data_.size()) {
        if (std::memcmp(payload + payload_offset, reassembled_data_.data() + buf_offset, compare_len) != 0) {
            stats_.conflict_count++;
            return true;
        }
    }
    return false;
}

void TCPHalfStream::consumeData(size_t bytes) {
    if (bytes >= reassembled_data_.size()) {
        consumed_bytes_offset_ += reassembled_data_.size();
        reassembled_data_.clear();
    } else {
        consumed_bytes_offset_ += bytes;
        reassembled_data_.erase(reassembled_data_.begin(), reassembled_data_.begin() + bytes);
    }
}

// ============================================================================
// TCPConnectionStream Implementation
// ============================================================================

TCPConnectionStream::TCPConnectionStream(uint64_t stream_id,
                                         const FiveTuple& initial_tuple,
                                         const StreamReassemblyConfig& config)
    : stream_id_(stream_id), initial_tuple_(initial_tuple), config_(config),
      fwd_stream_(config), rev_stream_(config) {
}

bool TCPConnectionStream::processPacket(const PacketJob& job) {
    uint64_t pkt_time_us = static_cast<uint64_t>(job.ts_sec) * 1000000ULL + job.ts_usec;
    last_activity_time_us_ = pkt_time_us;

    updateState(job.tcp_flags);

    // Determine direction: FORWARD matches initial_tuple, REVERSE is opposite
    bool is_forward = (job.tuple.src_ip == initial_tuple_.src_ip &&
                       job.tuple.src_port == initial_tuple_.src_port);

    const uint8_t* payload = (job.payload_offset < job.data.size() && job.payload_length > 0) ?
                             job.data.data() + job.payload_offset : nullptr;

    if (is_forward) {
        return fwd_stream_.processSegment(job.tcp_seq, job.tcp_ack, job.tcp_flags,
                                          payload, job.payload_length, pkt_time_us);
    } else {
        return rev_stream_.processSegment(job.tcp_seq, job.tcp_ack, job.tcp_flags,
                                          payload, job.payload_length, pkt_time_us);
    }
}

void TCPConnectionStream::updateState(uint8_t flags) {
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t RST = 0x04;

    if (flags & RST) {
        state_ = TCPStreamState::RESET;
        return;
    }

    switch (state_) {
        case TCPStreamState::NEW:
            if (flags & SYN) {
                state_ = (flags & ACK) ? TCPStreamState::ESTABLISHED : TCPStreamState::SYN_SEEN;
            } else {
                state_ = TCPStreamState::ESTABLISHED; // Mid-stream capture
            }
            break;
        case TCPStreamState::SYN_SEEN:
            if (flags & ACK) {
                state_ = TCPStreamState::ESTABLISHED;
            }
            break;
        case TCPStreamState::ESTABLISHED:
            if (flags & FIN) {
                state_ = TCPStreamState::FIN_SEEN;
            }
            break;
        case TCPStreamState::FIN_SEEN:
            if (fwd_stream_.isComplete() && rev_stream_.isComplete()) {
                state_ = TCPStreamState::CLOSED;
            }
            break;
        default:
            break;
    }
}

StreamRecordSummary TCPConnectionStream::getSummary() const {
    StreamRecordSummary s;
    s.stream_id = stream_id_;
    s.tuple = initial_tuple_;
    s.state = state_;
    s.fwd = fwd_stream_.getStats();
    s.rev = rev_stream_.getStats();
    s.fwd_payload = fwd_stream_.getReassembledData();
    s.rev_payload = rev_stream_.getReassembledData();
    
    // Parse protocol metadata if payloads available
    if (!s.fwd_payload.empty()) {
        auto req_msgs = HTTPStreamParser::parseStream(s.fwd_payload.data(), s.fwd_payload.size());
        s.http_messages.insert(s.http_messages.end(), req_msgs.begin(), req_msgs.end());
        auto tls = TLSStreamParser::parseStream(s.fwd_payload.data(), s.fwd_payload.size());
        if (!tls.sni.empty() || tls.has_client_hello) {
            s.tls_meta = tls;
        }
    }
    if (!s.rev_payload.empty()) {
        auto resp_msgs = HTTPStreamParser::parseStream(s.rev_payload.data(), s.rev_payload.size());
        s.http_messages.insert(s.http_messages.end(), resp_msgs.begin(), resp_msgs.end());
    }
    return s;
}

// ============================================================================
// TCPStreamManager Implementation
// ============================================================================

TCPStreamManager::TCPStreamManager(const StreamReassemblyConfig& config)
    : config_(config) {
}

TCPConnectionStream* TCPStreamManager::processPacket(const PacketJob& job) {
    // Only reassemble TCP packets
    if (job.tuple.protocol != 6) {
        return nullptr;
    }

    FiveTuple canonical = job.tuple.toCanonical();
    auto it = active_streams_.find(canonical);

    if (it != active_streams_.end()) {
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_it);
        it->second.stream->processPacket(job);
        return it->second.stream.get();
    }

    // Check capacity
    if (active_streams_.size() >= config_.max_active_streams ||
        current_total_memory_ >= config_.max_total_reassembly_memory) {
        evictOldest();
    }

    uint64_t id = ++stream_sequence_;
    auto stream = std::make_unique<TCPConnectionStream>(id, job.tuple, config_);
    stream->processPacket(job);

    lru_list_.push_front(canonical);
    auto inserted = active_streams_.emplace(canonical, StreamNode{std::move(stream), lru_list_.begin()});

    current_total_memory_ += inserted.first->second.stream->getTotalBufferedMemory();
    return inserted.first->second.stream.get();
}

TCPConnectionStream* TCPStreamManager::getStream(const FiveTuple& tuple) {
    FiveTuple canonical = tuple.toCanonical();
    auto it = active_streams_.find(canonical);
    if (it != active_streams_.end()) {
        lru_list_.splice(lru_list_.begin(), lru_list_, it->second.lru_it);
        return it->second.stream.get();
    }
    return nullptr;
}

void TCPStreamManager::evictOldest() {
    if (lru_list_.empty()) return;

    FiveTuple oldest = lru_list_.back();
    auto it = active_streams_.find(oldest);
    if (it != active_streams_.end()) {
        size_t mem = it->second.stream->getTotalBufferedMemory();
        if (current_total_memory_ >= mem) current_total_memory_ -= mem;
        else current_total_memory_ = 0;

        finalized_summaries_.push_back(it->second.stream->getSummary());
        active_streams_.erase(it);
    }
    lru_list_.pop_back();
}

size_t TCPStreamManager::cleanupInactive(uint64_t current_time_us) {
    size_t evicted = 0;
    for (auto it = active_streams_.begin(); it != active_streams_.end(); ) {
        uint64_t last_time = it->second.stream->getLastActivityTimeUs();
        if (current_time_us > last_time &&
            (current_time_us - last_time) >= config_.stream_inactivity_timeout_us) {
            
            size_t mem = it->second.stream->getTotalBufferedMemory();
            if (current_total_memory_ >= mem) current_total_memory_ -= mem;
            else current_total_memory_ = 0;

            finalized_summaries_.push_back(it->second.stream->getSummary());
            lru_list_.erase(it->second.lru_it);
            it = active_streams_.erase(it);
            evicted++;
        } else {
            ++it;
        }
    }
    return evicted;
}

void TCPStreamManager::finalizeAll() {
    for (const auto& pair : active_streams_) {
        finalized_summaries_.push_back(pair.second.stream->getSummary());
    }
    active_streams_.clear();
    lru_list_.clear();
    current_total_memory_ = 0;
}

std::string TCPStreamManager::generateStreamStatsReport() const {
    size_t total = finalized_summaries_.size() + active_streams_.size();
    uint64_t total_fwd_bytes = 0;
    uint64_t total_rev_bytes = 0;
    uint32_t total_ooo = 0;
    uint32_t total_retrans = 0;
    uint32_t total_overlaps = 0;
    uint32_t total_gaps = 0;

    auto tally = [&](const StreamRecordSummary& s) {
        total_fwd_bytes += s.fwd.bytes_reassembled;
        total_rev_bytes += s.rev.bytes_reassembled;
        total_ooo += (s.fwd.out_of_order_count + s.rev.out_of_order_count);
        total_retrans += (s.fwd.retrans_count + s.rev.retrans_count);
        total_overlaps += (s.fwd.overlap_count + s.rev.overlap_count);
        total_gaps += (s.fwd.gap_count + s.rev.gap_count);
    };

    for (const auto& s : finalized_summaries_) tally(s);
    for (const auto& p : active_streams_) tally(p.second.stream->getSummary());

    std::ostringstream ss;
    ss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    ss << "║              TCP STREAM REASSEMBLY REPORT                    ║\n";
    ss << "╠══════════════════════════════════════════════════════════════╣\n";
    ss << "║ Total Streams Tracked:        " << std::setw(10) << total << "                     ║\n";
    ss << "║ Active Streams:               " << std::setw(10) << active_streams_.size() << "                     ║\n";
    ss << "║ Finalized Streams:            " << std::setw(10) << finalized_summaries_.size() << "                     ║\n";
    ss << "║ Total Reassembled Fwd Bytes:  " << std::setw(10) << total_fwd_bytes << "                     ║\n";
    ss << "║ Total Reassembled Rev Bytes:  " << std::setw(10) << total_rev_bytes << "                     ║\n";
    ss << "║ Total Out-of-Order Segments:  " << std::setw(10) << total_ooo << "                     ║\n";
    ss << "║ Total Retransmissions:        " << std::setw(10) << total_retrans << "                     ║\n";
    ss << "║ Total Overlaps Detected:      " << std::setw(10) << total_overlaps << "                     ║\n";
    ss << "║ Total Gaps Detected:          " << std::setw(10) << total_gaps << "                     ║\n";
    ss << "╚══════════════════════════════════════════════════════════════╝\n";
    return ss.str();
}

} // namespace DPI
