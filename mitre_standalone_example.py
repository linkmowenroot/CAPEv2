#!/usr/bin/env python3
"""
Example script showing how to use the standalone MITRE ATT&CK integration
with custom analysis data and signatures.
"""

import json
import os
import sys

# Add the standalone module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mitre_standalone'))

from signature_engine import SignatureEngine
from ttp_mapper import map_ttps
from mitre_integration import MitreAttackIntegration
from signature_base import ProcessSignature, NetworkSignature


# Example custom signatures
class RansomwareIndicators(ProcessSignature):
    """Detects potential ransomware indicators."""
    
    name = "ransomware_indicators"
    description = "Detects potential ransomware behavior"
    severity = 4
    confidence = 95
    weight = 5
    categories = ["ransomware", "malware"]
    families = ["generic_ransomware"]
    ttps = ["T1486", "T1083"]  # Data Encrypted for Impact, File and Directory Discovery
    mbcs = ["F0001", "E1486"]
    
    def run(self) -> bool:
        # Check for file encryption processes
        encryption_processes = ["cipher.exe", "bcdedit.exe", "vssadmin.exe"]
        
        for process in encryption_processes:
            if self.check_process_name(process):
                if process == "vssadmin.exe":
                    if self.check_command_line("delete shadows", regex=False):
                        self.add_match("Shadow copy deletion detected")
                        return True
                elif process == "bcdedit.exe":
                    if self.check_command_line("bootstatuspolicy ignoreallfailures", regex=False):
                        self.add_match("Boot recovery modification detected")
                        return True
                else:
                    self.add_match(f"Encryption-related process detected: {process}")
                    return True
        
        return False


class CryptocurrencyMining(ProcessSignature):
    """Detects cryptocurrency mining activity."""
    
    name = "cryptocurrency_mining"
    description = "Detects cryptocurrency mining processes"
    severity = 2
    confidence = 80
    weight = 2
    categories = ["mining", "resource-abuse"]
    ttps = ["T1496"]  # Resource Hijacking
    mbcs = ["E1496"]
    
    def run(self) -> bool:
        # Check for known mining processes
        mining_processes = ["xmrig.exe", "minerd.exe", "cgminer.exe", "bfgminer.exe"]
        
        for process in mining_processes:
            if self.check_process_name(process):
                self.add_match(f"Cryptocurrency mining process detected: {process}")
                return True
        
        # Check for mining pool connections
        mining_pools = ["pool.supportxmr.com", "xmrpool.eu", "minexmr.com"]
        network_data = self.analysis_data.get("network", {})
        connections = network_data.get("tcp", [])
        
        for connection in connections:
            for pool in mining_pools:
                if pool in connection.get("dst", ""):
                    self.add_match(f"Connection to mining pool: {pool}")
                    return True
        
        return False


class AdvancedPersistence(NetworkSignature):
    """Detects advanced persistence techniques."""
    
    name = "advanced_persistence"
    description = "Detects advanced persistence mechanisms"
    severity = 3
    confidence = 85
    weight = 3
    categories = ["persistence", "advanced"]
    ttps = ["T1053.005", "T1574.001"]  # Scheduled Task, DLL Search Order Hijacking
    mbcs = ["F0012", "E1053", "E1574"]
    
    def run(self) -> bool:
        # Check for scheduled task creation
        if self.check_http_request("/api/tasks", regex=False):
            self.add_match("Remote task scheduling detected")
            return True
        
        # Check for DLL hijacking indicators
        if self.check_http_request(r"\.dll$", regex=True):
            self.add_match("Suspicious DLL download detected")
            return True
        
        return False


def create_custom_analysis_data():
    """Create more comprehensive analysis data for testing."""
    return {
        "processes": [
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File malware.ps1",
                "pid": 1234
            },
            {
                "process_name": "vssadmin.exe",
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "pid": 5678
            },
            {
                "process_name": "bcdedit.exe", 
                "command_line": "bcdedit.exe /set bootstatuspolicy ignoreallfailures",
                "pid": 9012
            },
            {
                "process_name": "xmrig.exe",
                "command_line": "xmrig.exe -o pool.supportxmr.com:443 -u wallet_address",
                "pid": 3456
            }
        ],
        "network": {
            "http": [
                {
                    "uri": "/download/payload.exe",
                    "host": "malicious-domain.com",
                    "method": "GET"
                },
                {
                    "uri": "/api/tasks",
                    "host": "c2-server.evil",
                    "method": "POST"
                },
                {
                    "uri": "/libraries/evil.dll",
                    "host": "malware-repo.net",
                    "method": "GET"
                }
            ],
            "dns": [
                {
                    "request": "malicious-domain.com",
                    "type": "A"
                },
                {
                    "request": "pool.supportxmr.com",
                    "type": "A"
                }
            ],
            "tcp": [
                {
                    "src": "192.168.1.100",
                    "dst": "pool.supportxmr.com:443",
                    "bytes": 1048576
                }
            ]
        },
        "file_operations": [
            {
                "operation": "create",
                "filename": "C:\\temp\\ransomware.exe"
            },
            {
                "operation": "write",
                "filename": "C:\\Users\\user\\Desktop\\README_DECRYPT.txt"
            },
            {
                "operation": "delete",
                "filename": "C:\\Users\\user\\Documents\\important.docx"
            }
        ],
        "registry_operations": [
            {
                "operation": "set",
                "key": "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "SecurityUpdate",
                "data": "C:\\temp\\ransomware.exe"
            },
            {
                "operation": "set",
                "key": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
                "value": "MaxSize",
                "data": "0"
            }
        ]
    }


def main():
    """Example usage of the standalone MITRE integration."""
    print("=== Standalone MITRE ATT&CK Integration Example ===\n")
    
    # Create custom analysis data
    print("1. Creating custom analysis data...")
    analysis_data = create_custom_analysis_data()
    
    # Save analysis data to file for demonstration
    with open('example_analysis.json', 'w') as f:
        json.dump(analysis_data, f, indent=2)
    print("   Saved analysis data to: example_analysis.json")
    
    # Initialize signature engine
    print("\n2. Initializing signature engine...")
    engine = SignatureEngine()
    
    # Add custom signatures
    print("   Adding custom signatures...")
    custom_signatures = [RansomwareIndicators, CryptocurrencyMining, AdvancedPersistence]
    for sig_class in custom_signatures:
        engine.add_signature_class(sig_class)
    
    # Also add some built-in signatures for comparison
    from sample_signatures import PowerShellExecution, SuspiciousHttpRequest
    engine.add_signature_class(PowerShellExecution)
    engine.add_signature_class(SuspiciousHttpRequest)
    
    # Run signatures
    print(f"\n3. Running {len(engine.signatures)} signatures...")
    matched_signatures = engine.run_signatures(analysis_data)
    
    # Print results
    print(f"\n4. Results:")
    engine.print_results()
    
    # Map TTPs
    print(f"\n5. Mapping TTPs...")
    ttps_data = map_ttps(engine.get_ttps(), engine.get_mbcs())
    
    # Generate MITRE ATT&CK matrix
    print(f"\n6. Generating MITRE ATT&CK matrix...")
    mitre = MitreAttackIntegration(use_online=False)  # Use offline mode for this example
    attack_matrix = mitre.generate_attack_matrix(ttps_data)
    
    # Print matrix summary
    mitre.print_matrix_summary(attack_matrix)
    
    # Export to JSON
    output_file = "example_mitre_results.json"
    print(f"\n7. Exporting results to: {output_file}")
    mitre.export_to_json(attack_matrix, output_file)
    
    # Show some statistics
    print(f"\n=== Final Statistics ===")
    tactic_coverage = mitre.get_tactic_coverage(attack_matrix)
    for tactic, stats in tactic_coverage.items():
        print(f"{tactic.upper()}: {stats['technique_count']} techniques ({stats['percentage']:.1f}%)")
    
    print(f"\nFiles created:")
    print(f"  - example_analysis.json (input data)")
    print(f"  - {output_file} (MITRE results)")
    
    print(f"\nExample completed successfully!")


if __name__ == "__main__":
    main()