#include "load_balancer.h"
#include <iostream>
#include <chrono>

namespace DPI {

// ============================================================================
// LoadBalancer Implementation
// ============================================================================

LoadBalancer::LoadBalancer(int lb_id,
                           std::vector<ThreadSafeQueue<PacketJob>*> fp_queues,
                           int fp_start_id,
                           int total_fps)
    : lb_id_(lb_id),
      fp_start_id_(fp_start_id),
      num_fps_(static_cast<int>(fp_queues.size())),
      total_fps_(total_fps > 0 ? total_fps : static_cast<int>(fp_queues.size())),
      input_queue_(10000),
      fp_queues_(std::move(fp_queues)),
      per_fp_counts_(num_fps_, 0) {
}

LoadBalancer::~LoadBalancer() {
    stop();
}

void LoadBalancer::start() {
    if (running_) return;
    
    running_ = true;
    thread_ = std::thread(&LoadBalancer::run, this);
    
    std::cout << "[LB" << lb_id_ << "] Started (serving FP" 
              << fp_start_id_ << "-FP" << (fp_start_id_ + num_fps_ - 1) << ")\n";
}

void LoadBalancer::stop() {
    if (!running_) return;
    
    running_ = false;
    input_queue_.shutdown();
    
    if (thread_.joinable()) {
        thread_.join();
    }
    
    std::cout << "[LB" << lb_id_ << "] Stopped\n";
}

void LoadBalancer::run() {
    while (running_) {
        // Get packet from input queue (with timeout to check running flag)
        auto job_opt = input_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (!job_opt) {
            continue;  // Timeout or shutdown
        }
        
        packets_received_++;
        
        // Select target FP based on deterministic flow hash
        int fp_index = selectFP(*job_opt);
        
        // Push to selected FP's queue
        if (fp_index >= 0 && static_cast<size_t>(fp_index) < fp_queues_.size()) {
            fp_queues_[fp_index]->push(std::move(*job_opt));
            packets_dispatched_++;
            if (static_cast<size_t>(fp_index) < per_fp_counts_.size()) {
                per_fp_counts_[fp_index]++;
            }
        }
    }
}

int LoadBalancer::selectFP(const FiveTuple& tuple) {
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    size_t effective_total = total_fps_ > 0 ? total_fps_ : num_fps_;
    size_t global_fp = hash % effective_total;
    return static_cast<int>(global_fp % num_fps_);
}

int LoadBalancer::selectFP(const PacketJob& job) {
    if (total_fps_ > 0 && job.target_fp < static_cast<size_t>(total_fps_)) {
        return static_cast<int>(job.target_fp % num_fps_);
    }
    return selectFP(job.tuple);
}

LoadBalancer::LBStats LoadBalancer::getStats() const {
    LBStats stats;
    stats.packets_received = packets_received_.load();
    stats.packets_dispatched = packets_dispatched_.load();
    
    stats.per_fp_packets = per_fp_counts_;
    
    return stats;
}

// ============================================================================
// LBManager Implementation
// ============================================================================

LBManager::LBManager(int num_lbs, int fps_per_lb,
                     std::vector<ThreadSafeQueue<PacketJob>*> fp_queues)
    : fps_per_lb_(fps_per_lb) {
    
    int total_fps = num_lbs * fps_per_lb;
    
    // Create load balancers, each handling a subset of FPs
    for (int lb_id = 0; lb_id < num_lbs; lb_id++) {
        std::vector<ThreadSafeQueue<PacketJob>*> lb_fp_queues;
        int fp_start = lb_id * fps_per_lb;
        
        for (int i = 0; i < fps_per_lb; i++) {
            lb_fp_queues.push_back(fp_queues[fp_start + i]);
        }
        
        lbs_.push_back(std::make_unique<LoadBalancer>(lb_id, lb_fp_queues, fp_start, total_fps));
    }
    
    std::cout << "[LBManager] Created " << num_lbs << " load balancers, "
              << fps_per_lb << " FPs each (total FPs: " << total_fps << ")\n";
}

LBManager::~LBManager() {
    stopAll();
}

void LBManager::startAll() {
    for (auto& lb : lbs_) {
        lb->start();
    }
}

void LBManager::stopAll() {
    for (auto& lb : lbs_) {
        lb->stop();
    }
}

LoadBalancer& LBManager::getLBForPacket(const FiveTuple& tuple) {
    // Deterministic two-tier load balancing without modulo collision
    FiveTupleHash hasher;
    size_t hash = hasher(tuple);
    size_t total_fps = lbs_.size() * fps_per_lb_;
    size_t global_fp = hash % total_fps;
    size_t lb_index = global_fp / fps_per_lb_;
    return *lbs_[lb_index];
}

LBManager::AggregatedStats LBManager::getAggregatedStats() const {
    AggregatedStats stats = {0, 0};
    
    for (const auto& lb : lbs_) {
        auto lb_stats = lb->getStats();
        stats.total_received += lb_stats.packets_received;
        stats.total_dispatched += lb_stats.packets_dispatched;
    }
    
    return stats;
}

} // namespace DPI
