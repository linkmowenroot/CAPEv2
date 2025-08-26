# Tracee & Traffic to MITRE Standalone Converter

This conversion script transforms CAPEv2 analysis reports from Tracee (eBPF-based Linux analysis) and Traffic (network analysis) into the format expected by `mitre_standalone.py` for MITRE ATT&CK integration and behavioral analysis.

## What it does

The script extracts and converts:

### From `tracee.json.analysis.json`:
- **Processes**: Process tree information with PIDs, parent relationships, and creation details
- **File Operations**: System calls like `openat`, `write`, `read`, `unlink` mapped to file operations
- **Registry-like Operations**: Linux configuration file modifications (equivalent to Windows registry changes)

### From `traffic.json`:
- **HTTP Requests**: Web traffic with URLs, methods, and hosts
- **DNS Queries**: Domain name resolution requests
- **TCP/UDP Connections**: Network connections with source/destination details

## Usage

### Basic Usage
```bash
# Convert reports and save to file
python convert_to_mitre_standalone.py --tracee report/tracee.json.analysis.json --traffic report/traffic.json --output converted_analysis.json
```

### Advanced Usage
```bash
# Convert and run MITRE analysis automatically
python convert_to_mitre_standalone.py --tracee report/tracee.json.analysis.json --traffic report/traffic.json --output converted.json --run-mitre

# Verbose output for debugging
python convert_to_mitre_standalone.py --tracee report/tracee.json.analysis.json --traffic report/traffic.json --output converted.json --verbose
```

### Using the converted data with mitre_standalone.py
```bash
# After conversion, run MITRE analysis
python mitre_standalone/mitre_standalone.py --input converted_analysis.json --output mitre_results.json
```

## Command Line Arguments

- `--tracee`, `-t`: Path to `tracee.json.analysis.json` file (required)
- `--traffic`, `-r`: Path to `traffic.json` file (required)
- `--output`, `-o`: Output file path for converted data (default: `converted_analysis.json`)
- `--verbose`, `-v`: Enable verbose logging
- `--run-mitre`: Automatically run `mitre_standalone.py` after conversion

## Output Format

The script produces a JSON file compatible with `mitre_standalone.py` containing:

```json
{
  "metadata": {
    "conversion_timestamp": "...",
    "source_files": {
      "tracee": "...",
      "traffic": "..."
    },
    "converter_version": "1.0.0"
  },
  "processes": [
    {
      "process_name": "malware",
      "command_line": "PARENT PROCESS (PID: 3135)",
      "pid": 3135,
      "parent_pid": 0
    }
  ],
  "network": {
    "http": [...],
    "dns": [...],
    "tcp": [...],
    "udp": [...]
  },
  "file_operations": [
    {
      "operation": "open",
      "filename": "/etc/passwd",
      "timestamp": 1755516960970167974,
      "process_id": 3468,
      "process_name": "bash"
    }
  ],
  "registry_operations": [...]
}
```

## Integration with MITRE ATT&CK

After conversion, the data can be analyzed with `mitre_standalone.py` to:

1. **Run behavioral signatures** against the extracted data
2. **Map activities to MITRE ATT&CK TTPs** (Tactics, Techniques, Procedures)
3. **Generate MITRE ATT&CK matrix** showing detected techniques
4. **Export results** for further analysis or reporting

## Example Workflow

```bash
# 1. Convert your analysis reports
python convert_to_mitre_standalone.py \
  --tracee report/tracee.json.analysis.json \
  --traffic report/traffic.json \
  --output analysis_converted.json

# 2. Run MITRE analysis
python mitre_standalone/mitre_standalone.py \
  --input analysis_converted.json \
  --output mitre_attack_results.json

# 3. View results
cat mitre_attack_results.json | jq '.mitre_attack_matrix'
```

## Requirements

- Python 3.6+
- `json` (built-in)
- Access to `mitre_standalone/` directory for MITRE analysis

## Supported Data Sources

- **Tracee eBPF**: Linux system call tracing and behavioral analysis
- **Traffic Analysis**: Network packet capture and analysis (tcpdump-based)

## Notes

- The script handles large tracee files efficiently by streaming JSON processing
- File operations are extracted from Linux syscalls (`openat`, `write`, `read`, etc.)
- Network data is normalized to match `mitre_standalone.py` expectations
- Registry operations are simulated for Linux by tracking configuration file changes
- All timestamps are preserved for temporal analysis