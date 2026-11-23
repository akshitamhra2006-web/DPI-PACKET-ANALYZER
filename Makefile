CXX ?= clang++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2 -I include
ASAN_FLAGS = -fsanitize=address -g -fno-omit-frame-pointer
TSAN_FLAGS = -fsanitize=thread -g -fno-omit-frame-pointer
UBSAN_FLAGS = -fsanitize=undefined -g -fno-omit-frame-pointer
LDFLAGS = -lpthread

CORE_SRCS = src/dpi_engine.cpp \
            src/fast_path.cpp \
            src/load_balancer.cpp \
            src/connection_tracker.cpp \
            src/rule_manager.cpp \
            src/sni_extractor.cpp \
            src/packet_parser.cpp \
            src/pcap_reader.cpp \
            src/types.cpp \
            src/logger.cpp \
            src/flow_record.cpp \
            src/flow_table.cpp \
            src/detection_types.cpp \
            src/detection_config.cpp \
            src/behavioral_detectors.cpp \
            src/detection_engine.cpp \
            src/stream_types.cpp \
            src/tcp_stream_reassembler.cpp \
            src/http_stream_parser.cpp \
            src/tls_stream_parser.cpp \
            src/dns_intelligence.cpp \
            src/incident_types.cpp \
            src/incident_config.cpp \
            src/incident_correlator.cpp \
            src/signature_types.cpp \
            src/signature_validator.cpp \
            src/signature_parser.cpp \
            src/signature_matcher.cpp \
            src/signature_manager.cpp \
            src/signature_engine.cpp \
            src/threat_intel_types.cpp \
            src/threat_intel_validator.cpp \
            src/threat_intel_parser.cpp \
            src/threat_intel_manager.cpp \
            src/threat_intel_engine.cpp \
            src/risk_profiler.cpp \
            src/network_analytics.cpp \
            src/investigation_types.cpp \
            src/investigation_manager.cpp \
            src/report_generator.cpp

MAIN_SRC = src/main_dpi.cpp
TEST_SRC = tests/test_main.cpp

BIN_DIR = bin
TARGET = $(BIN_DIR)/dpi_engine
ASAN_TARGET = $(BIN_DIR)/dpi_engine_asan
TEST_TARGET = $(BIN_DIR)/dpi_tests
TEST_ASAN_TARGET = $(BIN_DIR)/dpi_tests_asan
TEST_TSAN_TARGET = $(BIN_DIR)/dpi_tests_tsan
TEST_UBSAN_TARGET = $(BIN_DIR)/dpi_tests_ubsan

.PHONY: all clean test test_asan test_tsan test_ubsan asan dirs help

all: dirs $(TARGET)

dirs:
	@mkdir -p $(BIN_DIR)

$(TARGET): $(MAIN_SRC) $(CORE_SRCS)
	$(CXX) $(CXXFLAGS) $(MAIN_SRC) $(CORE_SRCS) $(LDFLAGS) -o $@

asan: dirs $(ASAN_TARGET)

$(ASAN_TARGET): $(MAIN_SRC) $(CORE_SRCS)
	$(CXX) $(CXXFLAGS) $(ASAN_FLAGS) $(MAIN_SRC) $(CORE_SRCS) $(LDFLAGS) -o $@

$(TEST_TARGET): $(TEST_SRC) $(CORE_SRCS)
	$(CXX) $(CXXFLAGS) $(TEST_SRC) $(CORE_SRCS) $(LDFLAGS) -o $@

$(TEST_ASAN_TARGET): $(TEST_SRC) $(CORE_SRCS)
	$(CXX) $(CXXFLAGS) $(ASAN_FLAGS) $(TEST_SRC) $(CORE_SRCS) $(LDFLAGS) -o $@

test: dirs $(TEST_TARGET)
	@echo "Running DPI Test Suite..."
	@./$(TEST_TARGET)

test_asan: dirs $(TEST_ASAN_TARGET)
	@echo "Running DPI Test Suite with AddressSanitizer..."
	@./$(TEST_ASAN_TARGET)

$(TEST_TSAN_TARGET): $(TEST_SRC) $(CORE_SRCS)
	$(CXX) $(CXXFLAGS) $(TSAN_FLAGS) $(TEST_SRC) $(CORE_SRCS) $(LDFLAGS) -o $@

test_tsan: dirs $(TEST_TSAN_TARGET)
	@echo "Running DPI Test Suite with ThreadSanitizer..."
	@./$(TEST_TSAN_TARGET)

$(TEST_UBSAN_TARGET): $(TEST_SRC) $(CORE_SRCS)
	$(CXX) $(CXXFLAGS) $(UBSAN_FLAGS) $(TEST_SRC) $(CORE_SRCS) $(LDFLAGS) -o $@

test_ubsan: dirs $(TEST_UBSAN_TARGET)
	@echo "Running DPI Test Suite with UndefinedBehaviorSanitizer..."
	@./$(TEST_UBSAN_TARGET)

clean:
	rm -rf $(BIN_DIR) /tmp/test_out.pcap

help:
	@echo "Available targets:"
	@echo "  make              - Build production dpi_engine"
	@echo "  make asan         - Build dpi_engine with AddressSanitizer"
	@echo "  make test         - Build and run comprehensive unit & integration tests"
	@echo "  make test_asan    - Build and run tests with AddressSanitizer"
	@echo "  make clean        - Remove build artifacts"
