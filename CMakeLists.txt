cmake_minimum_required(VERSION 3.16)
project(PacketAnalyzer VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Option for AddressSanitizer
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()

# Core DPI library sources (modular architecture)
set(DPI_CORE_SOURCES
    src/dpi_engine.cpp
    src/fast_path.cpp
    src/load_balancer.cpp
    src/connection_tracker.cpp
    src/rule_manager.cpp
    src/sni_extractor.cpp
    src/packet_parser.cpp
    src/pcap_reader.cpp
    src/types.cpp
    src/logger.cpp
    src/flow_record.cpp
    src/flow_table.cpp
    src/detection_types.cpp
    src/detection_config.cpp
    src/behavioral_detectors.cpp
    src/detection_engine.cpp
    src/stream_types.cpp
    src/tcp_stream_reassembler.cpp
    src/http_stream_parser.cpp
    src/tls_stream_parser.cpp
    src/dns_intelligence.cpp
    src/incident_types.cpp
    src/incident_config.cpp
    src/incident_correlator.cpp
    src/signature_types.cpp
    src/signature_validator.cpp
    src/signature_parser.cpp
    src/signature_matcher.cpp
    src/signature_manager.cpp
    src/signature_engine.cpp
    src/threat_intel_types.cpp
    src/threat_intel_validator.cpp
    src/threat_intel_parser.cpp
    src/threat_intel_manager.cpp
    src/threat_intel_engine.cpp
    src/risk_profiler.cpp
    src/network_analytics.cpp
    src/investigation_types.cpp
    src/investigation_manager.cpp
    src/report_generator.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/include)

find_package(Threads REQUIRED)

# Main DPI Engine executable
add_executable(dpi_engine src/main_dpi.cpp ${DPI_CORE_SOURCES})
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# Legacy simple packet analyzer
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
    add_executable(packet_analyzer src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp)
endif()

# Test Suite executable
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_main.cpp")
    add_executable(dpi_tests tests/test_main.cpp ${DPI_CORE_SOURCES})
    target_link_libraries(dpi_tests PRIVATE Threads::Threads)
    enable_testing()
    add_test(NAME AllDPITests COMMAND dpi_tests)
endif()
