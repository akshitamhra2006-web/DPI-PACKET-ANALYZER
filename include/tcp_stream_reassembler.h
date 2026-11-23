#ifndef DPI_TCP_STREAM_REASSEMBLER_H
#define DPI_TCP_STREAM_REASSEMBLER_H

#include "types.h"
#include "stream_types.h"
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>
#include <list>

namespace DPI {

// ============================================================================
// TCP Half-Stream (Unidirectional Reassembler)
// Tracks one direction of a TCP connection: sequence space, out-of-order queue,
// overlap trimming, and contiguous reassembled bytes.
// ============================================================================
class TCPHalfStream {
public:
    TCPHalfStream(const StreamReassemblyConfig& config = StreamReassemblyConfig{});

    // Ingest a TCP segment
    // Returns true if new contiguous bytes were appended to the reassembled stream
    bool processSegment(uint32_t seq, uint32_t ack, uint8_t flags,
                        const uint8_t* payload, size_t len, uint64_t timestamp_us);

    // Get contiguous reassembled payload bytes
    const std::vector<uint8_t>& getReassembledData() const { return reassembled_data_; }
    
    // Clear already-consumed reassembled bytes to save memory (tracking offset)
    void consumeData(size_t bytes);

    // Directional statistics & state
    const StreamDirectionStats& getStats() const { return stats_; }
    StreamDirectionStats& getStats() { return stats_; }
    
    size_t getBufferedOutOfOrderBytes() const { return buffered_bytes_; }
    size_t getOutOfOrderSegmentCount() const { return out_of_order_segments_.size(); }

    bool isComplete() const { return stats_.is_complete; }

private:
    StreamReassemblyConfig config_;
    StreamDirectionStats stats_;

    bool initialized_ = false;
    uint32_t fin_seq_ = 0;

    // Contiguous reassembled byte stream
    std::vector<uint8_t> reassembled_data_;
    size_t consumed_bytes_offset_ = 0; // Total bytes pruned so far

    // Out-of-order buffer: ordered by sequence number (using RFC sequence comparison)
    std::map<uint32_t, TCPSegment, SeqLessThan> out_of_order_segments_;
    size_t buffered_bytes_ = 0;

    // Helper to drain contiguous segments from out_of_order_segments_
    bool drainOutOfOrder();

    // Check overlap conflict between incoming bytes and existing contiguous stream
    bool checkConflict(uint32_t seq, const uint8_t* payload, size_t len);
};

// ============================================================================
// Bidirectional TCP Connection Stream
// Combines forward and reverse half-streams mapped to a FiveTuple.
// ============================================================================
class TCPConnectionStream {
public:
    TCPConnectionStream(uint64_t stream_id, const FiveTuple& initial_tuple,
                        const StreamReassemblyConfig& config = StreamReassemblyConfig{});

    // Process a packet job
    // Returns true if either direction produced new reassembled data
    bool processPacket(const PacketJob& job);

    uint64_t getStreamId() const { return stream_id_; }
    const FiveTuple& getInitialTuple() const { return initial_tuple_; }
    TCPStreamState getState() const { return state_; }
    uint64_t getLastActivityTimeUs() const { return last_activity_time_us_; }

    TCPHalfStream& getForwardStream() { return fwd_stream_; }
    const TCPHalfStream& getForwardStream() const { return fwd_stream_; }

    TCPHalfStream& getReverseStream() { return rev_stream_; }
    const TCPHalfStream& getReverseStream() const { return rev_stream_; }

    bool isComplete() const {
        return (fwd_stream_.isComplete() && rev_stream_.isComplete()) ||
               state_ == TCPStreamState::CLOSED || state_ == TCPStreamState::RESET;
    }

    size_t getTotalBufferedMemory() const {
        return fwd_stream_.getBufferedOutOfOrderBytes() +
               fwd_stream_.getReassembledData().size() +
               rev_stream_.getBufferedOutOfOrderBytes() +
               rev_stream_.getReassembledData().size();
    }

    // Generate summary record
    StreamRecordSummary getSummary() const;

private:
    uint64_t stream_id_;
    FiveTuple initial_tuple_;
    StreamReassemblyConfig config_;
    TCPStreamState state_ = TCPStreamState::NEW;
    uint64_t last_activity_time_us_ = 0;

    TCPHalfStream fwd_stream_;
    TCPHalfStream rev_stream_;

    void updateState(uint8_t flags);
};

// ============================================================================
// TCP Stream Manager
// Thread-local (or per-FP) manager for tracking all active streams,
// enforcing global and per-stream memory bounds and LRU eviction.
// ============================================================================
class TCPStreamManager {
public:
    TCPStreamManager(const StreamReassemblyConfig& config = StreamReassemblyConfig{});

    // Ingest a packet job into its corresponding stream
    // Returns pointer to TCPConnectionStream (or nullptr if dropped/rejected)
    TCPConnectionStream* processPacket(const PacketJob& job);

    // Find stream by tuple
    TCPConnectionStream* getStream(const FiveTuple& tuple);

    // Evict oldest or expired streams
    size_t cleanupInactive(uint64_t current_time_us);

    // Finalize all active streams
    void finalizeAll();

    // Accessors
    size_t getActiveStreamCount() const { return active_streams_.size(); }
    size_t getFinalizedStreamCount() const { return finalized_summaries_.size(); }
    size_t getTotalAllocatedMemory() const { return current_total_memory_; }

    const std::vector<StreamRecordSummary>& getFinalizedSummaries() const {
        return finalized_summaries_;
    }

    std::string generateStreamStatsReport() const;

private:
    StreamReassemblyConfig config_;
    uint64_t stream_sequence_ = 0;
    size_t current_total_memory_ = 0;

    struct StreamNode {
        std::unique_ptr<TCPConnectionStream> stream;
        std::list<FiveTuple>::iterator lru_it;
    };

    std::unordered_map<FiveTuple, StreamNode, FiveTupleHash> active_streams_;
    std::list<FiveTuple> lru_list_;
    std::vector<StreamRecordSummary> finalized_summaries_;

    void evictOldest();
};

} // namespace DPI

#endif // DPI_TCP_STREAM_REASSEMBLER_H
