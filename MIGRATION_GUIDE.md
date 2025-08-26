# Migration Guide: From CAPEv2 to Standalone MITRE ATT&CK Integration

This guide explains how to migrate MITRE ATT&CK functionality from CAPEv2 to the standalone module.

## Overview

The standalone module extracts the core MITRE ATT&CK integration functionality from CAPEv2 into independent components that can be used in any Python project without CAPEv2 dependencies.

## Architecture Comparison

### CAPEv2 Architecture
```
CAPEv2 Analysis → Signature Processing → TTP Extraction → MITRE Mapping → Web Display
      ↓                    ↓                   ↓              ↓
   Database         behavior.py        mapTTPs.py     mitre.py
   abstracts.py     plugins.py                        pyattck
```

### Standalone Architecture
```
Analysis Data → Signature Engine → TTP Mapper → MITRE Integration → JSON Export
     ↓               ↓               ↓              ↓
JSON Input    signature_engine.py  ttp_mapper.py  mitre_integration.py
            signature_base.py                     (optional pyattck)
```

## Key Differences

### Dependencies
- **CAPEv2**: Requires full CAPEv2 stack, Django, SQLAlchemy, etc.
- **Standalone**: Zero dependencies for offline mode, optional pyattck for online mode

### Data Input
- **CAPEv2**: Analysis results from sandbox execution
- **Standalone**: JSON format with behavioral data

### Output
- **CAPEv2**: Web interface + database storage
- **Standalone**: JSON files for easy integration

## Migration Steps

### 1. Extract Analysis Data

Convert your analysis results to the standalone JSON format:

```python
# CAPEv2 format (simplified)
capev2_results = {
    "behavior": {
        "processes": [...],
        "network": {...}
    },
    "signatures": [...]
}

# Standalone format
standalone_data = {
    "processes": capev2_results["behavior"]["processes"],
    "network": capev2_results["behavior"]["network"],
    "file_operations": [...],  # Extract from behavior logs
    "registry_operations": [...] # Extract from behavior logs
}
```

### 2. Migrate Signatures

Convert CAPEv2 signatures to standalone format:

```python
# CAPEv2 signature
from lib.cuckoo.common.abstracts import Signature

class MySignature(Signature):
    name = "my_detection"
    ttps = ["T1059.001"]
    
    def run(self):
        return self.check_file(pattern="*.exe", regex=True)

# Standalone signature  
from signature_base import FileSignature

class MySignature(FileSignature):
    name = "my_detection"
    ttps = ["T1059.001"]
    
    def run(self):
        return self.check_file_created(pattern=r".*\.exe$", regex=True)
```

### 3. Replace Processing Pipeline

Replace CAPEv2's processing with standalone components:

```python
# Instead of CAPEv2's behavior.py and plugins.py
from signature_engine import SignatureEngine
from ttp_mapper import map_ttps
from mitre_integration import MitreAttackIntegration

# Load and run signatures
engine = SignatureEngine()
engine.load_signatures_from_directory("./signatures/")
matched = engine.run_signatures(analysis_data)

# Map TTPs and generate MITRE matrix
ttps_data = map_ttps(engine.get_ttps(), engine.get_mbcs())
mitre = MitreAttackIntegration()
attack_matrix = mitre.generate_attack_matrix(ttps_data)

# Export results
mitre.export_to_json(attack_matrix, "results.json")
```

## Common Migration Patterns

### Signature Helper Methods

| CAPEv2 Method | Standalone Equivalent |
|---------------|----------------------|
| `self.check_file(pattern)` | `self.check_file_created(pattern)` |
| `self.check_mutex(pattern)` | Custom implementation needed |
| `self.check_api(api_name)` | Custom implementation needed |
| `self.check_ip(ip)` | Use NetworkSignature methods |

### Data Access Patterns

| CAPEv2 Access | Standalone Access |
|---------------|-------------------|
| `self.results["behavior"]["processes"]` | `self.analysis_data["processes"]` |
| `self.results["network"]["http"]` | `self.analysis_data["network"]["http"]` |
| `self.results["dropped"]` | `self.analysis_data["file_operations"]` |

### Configuration

| CAPEv2 Config | Standalone Config |
|---------------|-------------------|
| `reporting.conf` | Command line arguments |
| `behavior.conf` | SignatureEngine parameters |
| `mitre.conf` | MitreAttackIntegration parameters |

## Example Migration

Here's a complete example of migrating a CAPEv2 signature:

### Original CAPEv2 Signature
```python
from lib.cuckoo.common.abstracts import Signature

class PowerShellDownload(Signature):
    name = "powershell_download"
    description = "PowerShell downloads content from Internet"
    severity = 3
    categories = ["commands"]
    authors = ["CAPE"]
    minimum = "1.2"
    ttps = ["T1059.001", "T1105"]

    def run(self):
        for process in self.results["behavior"]["processes"]:
            if process["process_name"] == "powershell.exe":
                for call in process["calls"]:
                    if "DownloadFile" in call["api"]:
                        return True
        return False
```

### Migrated Standalone Signature
```python
from signature_base import ProcessSignature

class PowerShellDownload(ProcessSignature):
    name = "powershell_download"
    description = "PowerShell downloads content from Internet"
    severity = 3
    categories = ["commands"]
    authors = ["CAPE"]
    ttps = ["T1059.001", "T1105"]

    def run(self):
        if self.check_process_name("powershell.exe"):
            if self.check_command_line("DownloadFile"):
                self.add_match("PowerShell download detected")
                return True
        return False
```

## Integration Examples

### Command Line Integration
```bash
# Replace CAPEv2 processing
python mitre_standalone.py --input analysis.json --output mitre_results.json

# Use in scripts
results=$(python mitre_standalone.py --input analysis.json --output -)
echo "$results" | jq '.mitre_attack_matrix'
```

### Python Integration
```python
import json
from mitre_standalone.signature_engine import SignatureEngine
from mitre_standalone.mitre_integration import MitreAttackIntegration

# Load your analysis data
with open('analysis.json') as f:
    data = json.load(f)

# Process with signatures
engine = SignatureEngine()
engine.load_signatures_from_directory('./signatures/')
engine.run_signatures(data)

# Generate MITRE matrix
mitre = MitreAttackIntegration()
matrix = mitre.generate_attack_matrix(map_ttps(engine.get_ttps(), engine.get_mbcs()))

# Use results in your application
for tactic, techniques in matrix.items():
    print(f"Tactic: {tactic}")
    for technique in techniques:
        print(f"  - {technique['technique_id']}: {technique['technique_name']}")
```

### API Integration
```python
from flask import Flask, jsonify, request
from mitre_standalone.signature_engine import SignatureEngine

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    
    engine = SignatureEngine()
    engine.load_signatures_from_directory('./signatures/')
    matches = engine.run_signatures(data)
    
    return jsonify({
        'matched_signatures': matches,
        'ttps': engine.get_ttps()
    })
```

## Benefits of Migration

### Reduced Complexity
- No need for full CAPEv2 installation
- Simplified deployment and maintenance
- Easier testing and development

### Better Integration
- JSON-based input/output for easy integration
- Command-line interface for scripting
- Python library for programmatic access

### Enhanced Portability
- Works with any analysis framework
- Can be containerized easily
- No database dependencies

### Improved Performance
- Lightweight execution
- No web server overhead
- Faster processing for batch operations

## Limitations

### Reduced Functionality
- No web interface (JSON export only)
- Limited to behavioral analysis (no static analysis integration)
- Fewer built-in signature helpers

### Manual Signature Migration
- Each signature needs manual conversion
- Some CAPEv2-specific features may not be available
- API call monitoring requires custom implementation

## Best Practices

### Signature Development
1. Use appropriate base classes (ProcessSignature, NetworkSignature, etc.)
2. Add meaningful match descriptions with `add_match()`
3. Include proper MITRE technique IDs in `ttps`
4. Test signatures with sample data

### Data Preparation
1. Normalize your analysis data to the expected format
2. Include all relevant behavioral information
3. Use consistent field names and structures
4. Validate data before processing

### Performance Optimization
1. Use offline MITRE data for better performance
2. Filter signatures based on analysis type
3. Cache signature engines for repeated use
4. Process data in batches when possible

## Troubleshooting

### Common Issues
1. **Import errors**: Check Python path and module location
2. **Missing MITRE data**: Use offline mode or install pyattck
3. **Signature not matching**: Verify data format and signature logic
4. **Performance issues**: Use offline mode and optimize signature filtering

### Debug Mode
Enable verbose logging to diagnose issues:
```bash
python mitre_standalone.py --input analysis.json --verbose
```

## Support

For issues and questions:
1. Check the README.md for basic usage
2. Review example signatures in sample_signatures.py
3. Use the example script (mitre_standalone_example.py) as reference
4. Enable debug logging for detailed troubleshooting