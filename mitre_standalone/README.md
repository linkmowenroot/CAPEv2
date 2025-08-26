# Standalone MITRE ATT&CK Integration Module

A lightweight, independent module for integrating behavioral analysis with the MITRE ATT&CK framework. This module was extracted from CAPEv2 to provide a standalone solution that can be easily integrated into other malware analysis projects.

## Features

- **Signature-based behavior detection** with MITRE ATT&CK mapping
- **Offline operation** with embedded MITRE data (no external dependencies)
- **Online operation** with full MITRE ATT&CK data (requires pyattck)
- **Flexible signature system** supporting multiple detection types
- **JSON export** of MITRE ATT&CK matrices
- **Easy integration** into existing analysis pipelines

## Quick Start

### Basic Usage (Offline Mode)

```bash
# Run with sample data
python mitre_standalone.py --sample

# Process your own analysis data
python mitre_standalone.py --input your_analysis.json
```

### Advanced Usage

```bash
# Use online MITRE data (requires pyattck)
python mitre_standalone.py --sample --online

# Load custom signatures
python mitre_standalone.py --sample --signatures ./my_signatures/

# Save results to specific file
python mitre_standalone.py --sample --output my_results.json

# Verbose output
python mitre_standalone.py --sample --verbose
```

## Installation

### Minimal Installation (Offline Mode)
No external dependencies required for basic operation:

```bash
git clone <repository>
cd mitre_standalone
python mitre_standalone.py --sample
```

### Full Installation (Online Mode)
For online MITRE data support:

```bash
pip install pyattck requests
python mitre_standalone.py --sample --online
```

## Module Structure

```
mitre_standalone/
├── mitre_standalone.py      # Main execution script
├── signature_base.py        # Base signature classes
├── signature_engine.py      # Signature processing engine
├── ttp_mapper.py           # TTP mapping utilities
├── mitre_integration.py    # MITRE ATT&CK integration
├── sample_signatures.py   # Example signatures
├── requirements.txt        # Optional dependencies
└── README.md              # This file
```

## Core Components

### 1. Signature Base Classes

The module provides several base classes for creating signatures:

- `Signature`: Base class for all signatures
- `ProcessSignature`: For process-based detections
- `NetworkSignature`: For network-based detections  
- `FileSignature`: For file operation detections
- `RegistrySignature`: For registry operation detections

### 2. Signature Engine

The `SignatureEngine` class handles:
- Loading signatures from files or classes
- Executing signatures against analysis data
- Collecting TTPs and MBCs from matched signatures

### 3. TTP Mapping

The `ttp_mapper` module provides:
- Grouping TTPs by signature
- Removing duplicates
- Coverage statistics

### 4. MITRE Integration

The `MitreAttackIntegration` class handles:
- Online/offline MITRE ATT&CK data access
- Mapping TTPs to tactics and techniques
- Generating attack matrices
- JSON export functionality

## Creating Custom Signatures

### Basic Signature Example

```python
from signature_base import ProcessSignature

class MyCustomSignature(ProcessSignature):
    name = "my_custom_detection"
    description = "Detects my specific behavior"
    severity = 2
    confidence = 80
    categories = ["execution"]
    ttps = ["T1059.001"]  # MITRE technique ID
    
    def run(self) -> bool:
        if self.check_process_name("suspicious.exe"):
            self.add_match("Suspicious process detected")
            return True
        return False
```

### Network Signature Example

```python
from signature_base import NetworkSignature

class SuspiciousC2(NetworkSignature):
    name = "suspicious_c2_communication"
    description = "Detects C2 communication patterns"
    severity = 3
    confidence = 90
    categories = ["network", "c2"]
    ttps = ["T1071.001"]  # Web Protocols
    
    def run(self) -> bool:
        if self.check_http_request("malware-c2.com"):
            self.add_match("C2 communication detected")
            return True
        return False
```

## Analysis Data Format

The module expects analysis data in the following JSON format:

```json
{
    "processes": [
        {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -ExecutionPolicy Bypass",
            "pid": 1234
        }
    ],
    "network": {
        "http": [
            {
                "uri": "/download/payload.exe",
                "host": "malicious-domain.com",
                "method": "GET"
            }
        ],
        "dns": [
            {
                "request": "evil-server.com",
                "type": "A"
            }
        ]
    },
    "file_operations": [
        {
            "operation": "create",
            "filename": "C:\\temp\\malware.exe"
        }
    ],
    "registry_operations": [
        {
            "operation": "set",
            "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "value": "Malware",
            "data": "C:\\temp\\malware.exe"
        }
    ]
}
```

## Output Format

The module generates a JSON file with the MITRE ATT&CK matrix:

```json
{
    "mitre_attack_matrix": {
        "execution": [
            {
                "technique_id": "T1059.001",
                "technique_name": "Command and Scripting Interpreter: PowerShell",
                "description": "Adversaries may abuse PowerShell...",
                "signatures": ["powershell_execution"]
            }
        ],
        "persistence": [
            {
                "technique_id": "T1547.001", 
                "technique_name": "Boot or Logon Autostart Execution: Registry Run Keys",
                "description": "Adversaries may achieve persistence...",
                "signatures": ["persistence_registry_key"]
            }
        ]
    },
    "metadata": {
        "version": "1.0",
        "generated_by": "MITRE ATT&CK Standalone Integration",
        "data_source": "offline",
        "technique_count": 2,
        "tactic_count": 2,
        "tactics": ["execution", "persistence"]
    }
}
```

## Integration with Other Projects

### As a Library

```python
from signature_engine import SignatureEngine
from ttp_mapper import map_ttps
from mitre_integration import MitreAttackIntegration

# Load your analysis data
analysis_data = load_your_analysis_data()

# Run signatures
engine = SignatureEngine()
engine.load_signatures_from_directory("./my_signatures/")
matched_signatures = engine.run_signatures(analysis_data)

# Map TTPs and generate MITRE matrix
ttps_data = map_ttps(engine.get_ttps(), engine.get_mbcs())
mitre = MitreAttackIntegration()
attack_matrix = mitre.generate_attack_matrix(ttps_data)

# Export results
mitre.export_to_json(attack_matrix, "results.json")
```

### Command Line Integration

```bash
# In your analysis pipeline
python mitre_standalone.py --input analysis.json --output mitre_results.json

# Process results
cat mitre_results.json | jq '.mitre_attack_matrix'
```

## Extending the Module

### Adding New Signature Types

Create new base classes by inheriting from `Signature`:

```python
class MyCustomSignature(Signature):
    def check_my_custom_behavior(self, pattern):
        # Your custom detection logic
        pass
```

### Adding MITRE Data Sources

Extend the `MitreAttackIntegration` class:

```python
class CustomMitreIntegration(MitreAttackIntegration):
    def _load_custom_data_source(self):
        # Load data from your source
        pass
```

### Custom TTP Mappings

Modify the `DEFAULT_TTP_MAPPINGS` in `ttp_mapper.py` or provide your own mapping data.

## Migration from CAPEv2

This module extracts the core MITRE ATT&CK functionality from CAPEv2. To migrate:

1. **Replace signature imports**: Change from `lib.cuckoo.common.abstracts` to local imports
2. **Update data format**: Convert your analysis data to the expected JSON format  
3. **Replace execution**: Use `mitre_standalone.py` instead of CAPEv2's processing modules
4. **Customize signatures**: Port your existing signatures to the new base classes

## Troubleshooting

### Common Issues

1. **No signatures loaded**: Check signature file paths and class definitions
2. **MITRE data missing**: Use offline mode or install pyattck for online mode
3. **Analysis data format**: Ensure your data matches the expected schema

### Debug Mode

Run with verbose logging to diagnose issues:

```bash
python mitre_standalone.py --sample --verbose
```

## License

This module is derived from CAPEv2 and follows the same licensing terms. See the original project for details.

## Contributing

Contributions are welcome! Please:

1. Follow the existing code style
2. Add tests for new functionality
3. Update documentation
4. Submit pull requests

## Acknowledgments

This module is based on the MITRE ATT&CK integration from CAPEv2. Thanks to the CAPE developers and the MITRE ATT&CK team for their excellent work.