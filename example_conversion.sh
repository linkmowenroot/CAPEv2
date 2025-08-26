#!/bin/bash
#
# Example script for converting CAPEv2 tracee and traffic reports to MITRE format
# and running MITRE ATT&CK analysis
#
# Usage: ./example_conversion.sh [tracee_file] [traffic_file] [output_prefix]
#

set -e  # Exit on any error

# Default values
TRACEE_FILE="${1:-report/tracee.json.analysis.json}"
TRAFFIC_FILE="${2:-report/traffic.json}"
OUTPUT_PREFIX="${3:-analysis_$(date +%Y%m%d_%H%M%S)}"

CONVERTED_FILE="${OUTPUT_PREFIX}_converted.json"
MITRE_RESULTS="${OUTPUT_PREFIX}_mitre_results.json"

echo "=== CAPEv2 to MITRE Standalone Conversion ==="
echo "Tracee file: $TRACEE_FILE"
echo "Traffic file: $TRAFFIC_FILE"
echo "Output prefix: $OUTPUT_PREFIX"
echo ""

# Step 1: Convert the reports
echo "Step 1: Converting reports to MITRE format..."
python convert_to_mitre_standalone.py \
    --tracee "$TRACEE_FILE" \
    --traffic "$TRAFFIC_FILE" \
    --output "$CONVERTED_FILE" \
    --verbose

if [ $? -ne 0 ]; then
    echo "ERROR: Conversion failed!"
    exit 1
fi

echo ""

# Step 2: Run MITRE analysis
echo "Step 2: Running MITRE ATT&CK analysis..."
python mitre_standalone/mitre_standalone.py \
    --input "$CONVERTED_FILE" \
    --output "$MITRE_RESULTS" \
    --verbose

if [ $? -ne 0 ]; then
    echo "ERROR: MITRE analysis failed!"
    exit 1
fi

echo ""
echo "=== Analysis Complete ==="
echo "Converted data: $CONVERTED_FILE"
echo "MITRE results: $MITRE_RESULTS"
echo ""

# Display summary
echo "=== MITRE ATT&CK Results Summary ==="
if command -v jq &> /dev/null; then
    echo "Tactics detected:"
    jq -r '.metadata.tactics[]?' "$MITRE_RESULTS" 2>/dev/null || echo "No tactics found"
    echo ""
    echo "Techniques detected:"
    jq -r '.mitre_attack_matrix | to_entries[] | .value[] | "- \(.technique_id): \(.technique_name)"' "$MITRE_RESULTS" 2>/dev/null || echo "No techniques found"
else
    echo "Install 'jq' for formatted output"
    cat "$MITRE_RESULTS"
fi

echo ""
echo "Analysis completed successfully!"