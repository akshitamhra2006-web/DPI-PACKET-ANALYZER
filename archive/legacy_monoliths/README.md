# Archived Monolithic Implementations

These files represent early prototype monolithic implementations of the DPI engine that have been retired as part of Phase 2 stabilization:

- `main_working.cpp`: Early single-threaded prototype with rudimentary string-matching rules and inline flow tracking.
- `dpi_mt.cpp`: Early multi-threaded prototype that suffered from worker thread starvation (FP1/FP2 starved due to modulo collapse), out-of-order output writes, sleep-based synchronization, and naive substring matching false positives.
- `main_simple.cpp`: Minimal proof-of-concept runner.

## Migration Status: COMPLETE

All capabilities have been migrated into the modular production architecture:
- Core Engine: `include/dpi_engine.h`, `src/dpi_engine.cpp`, `src/main_dpi.cpp`
- Packet Processing & Fast Path: `include/fast_path.h`, `src/fast_path.cpp`
- Multi-tier Non-Collapsing Load Balancer: `include/load_balancer.h`, `src/load_balancer.cpp`
- O(1) LRU Connection Tracker: `include/connection_tracker.h`, `src/connection_tracker.cpp`
- Domain Boundary & Wildcard Rule Manager: `include/rule_manager.h`, `src/rule_manager.cpp`
- Safe Protocol Parsers & SNI Extractors: `include/packet_parser.h`, `src/packet_parser.cpp`, `include/sni_extractor.h`, `src/sni_extractor.cpp`
- Types & Symmetrical Flow Hash: `include/types.h`, `src/types.cpp`

These files are preserved here for historical reference only and are not part of the active build system.
