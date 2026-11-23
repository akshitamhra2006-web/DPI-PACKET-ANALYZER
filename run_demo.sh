#!/usr/bin/env bash
# ==============================================================================
# DPI & Packet Analyzer — Automated End-to-End Demonstration Script
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=============================================================================="
echo "    DPI & PACKET ANALYZER — COMPREHENSIVE PLATFORM DEMONSTRATION"
echo "=============================================================================="
echo ""

# 1. Verify build
echo "[1/5] Verifying C++17 modular DPI engine binary..."
if [ ! -f "bin/dpi_engine" ]; then
    echo "  -> Building binary bin/dpi_engine..."
    make all
else
    echo "  -> Found bin/dpi_engine (built and ready)."
fi

# 2. Generate synthetic fixtures
echo ""
echo "[2/5] Generating deterministic labeled PCAP test fixtures..."
python3 generate_all_fixtures.py

# 3. Execute DPI engine on capture with full analytics bundle export
echo ""
echo "[3/5] Executing full DPI engine pipeline on test capture..."
SESSION_DIR="data/current_session"
mkdir -p "$SESSION_DIR"

./bin/dpi_engine test_dpi.pcap "$SESSION_DIR/forwarded_traffic.pcap" \
    --analyze-all "$SESSION_DIR" \
    --detect \
    --incidents \
    --signatures \
    --threat-intelligence \
    --rules-dir config/signatures \
    --threat-intel-dir config/threat_intel \
    --risk-stats \
    --analytics-stats

# 4. Display generated artifacts
echo ""
echo "[4/5] Generated Unified Analysis Artifact Bundle in $SESSION_DIR:"
ls -lh "$SESSION_DIR"

# 5. Output instructions for Web Dashboard & API Server
echo ""
echo "=============================================================================="
echo "    DEMONSTRATION COMPLETED SUCCESSFULLY!"
echo "=============================================================================="
echo ""
echo "1. Self-Contained Offline HTML Report:"
echo "   file://$SCRIPT_DIR/$SESSION_DIR/analysis_report.html"
echo ""
echo "2. Launch the Web UI & REST API Server:"
echo "   python3 server/api_server.py"
echo "   Then navigate to: http://localhost:8080/"
echo ""
echo "3. Run the automated C++ test suite (180 tests):"
echo "   make test"
echo ""
echo "4. Run AddressSanitizer / UndefinedBehaviorSanitizer:"
echo "   make test_asan"
echo "   make test_ubsan"
echo "   make test_tsan"
echo "=============================================================================="
