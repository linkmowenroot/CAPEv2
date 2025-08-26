"""
MITRE ATT&CK Integration Module
"""

import logging
import json
import os
from typing import Dict, List, Any, Optional

log = logging.getLogger(__name__)


class MitreAttackIntegration:
    """MITRE ATT&CK framework integration for mapping TTPs to tactics and techniques."""
    
    def __init__(self, use_online: bool = False, data_path: Optional[str] = None):
        """
        Initialize MITRE ATT&CK integration.
        
        Args:
            use_online: Whether to use online MITRE data (requires pyattck)
            data_path: Path to local MITRE data files
        """
        self.use_online = use_online
        self.data_path = data_path
        self.mitre = None
        self.enterprise_data = {}
        
        self._initialize_mitre()
    
    def _initialize_mitre(self) -> None:
        """Initialize MITRE ATT&CK data source."""
        if self.use_online:
            self._initialize_online_mitre()
        else:
            self._initialize_offline_mitre()
    
    def _initialize_online_mitre(self) -> None:
        """Initialize MITRE ATT&CK using pyattck library."""
        try:
            from pyattck import Attck
            
            log.info("Initializing MITRE ATT&CK with online data...")
            self.mitre = Attck(nested_techniques=True)
            log.info("MITRE ATT&CK online initialization successful")
            
        except ImportError:
            log.error("pyattck library not found. Install with: pip install pyattck")
            self._fallback_to_offline()
        except Exception as e:
            log.error(f"Failed to initialize online MITRE ATT&CK: {e}")
            self._fallback_to_offline()
    
    def _initialize_offline_mitre(self) -> None:
        """Initialize MITRE ATT&CK using offline/embedded data."""
        log.info("Using offline MITRE ATT&CK data...")
        self.enterprise_data = self._get_embedded_mitre_data()
    
    def _fallback_to_offline(self) -> None:
        """Fallback to offline mode when online initialization fails."""
        log.warning("Falling back to offline MITRE ATT&CK data")
        self.use_online = False
        self._initialize_offline_mitre()
    
    def _get_embedded_mitre_data(self) -> Dict[str, Any]:
        """
        Get embedded MITRE ATT&CK data for common techniques.
        
        This is a simplified dataset for standalone operation.
        In a production environment, you would load this from the full MITRE data files.
        """
        return {
            "T1071": {
                "name": "Application Layer Protocol",
                "description": "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.",
                "tactics": ["command-and-control"]
            },
            "T1071.001": {
                "name": "Application Layer Protocol: Web Protocols",
                "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering.",
                "tactics": ["command-and-control"]
            },
            "T1112": {
                "name": "Modify Registry",
                "description": "Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.",
                "tactics": ["defense-evasion"]
            },
            "T1027": {
                "name": "Obfuscated Files or Information",
                "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit.",
                "tactics": ["defense-evasion"]
            },
            "T1027.002": {
                "name": "Obfuscated Files or Information: Software Packing",
                "description": "Adversaries may perform software packing or virtual machine software protection to conceal their code.",
                "tactics": ["defense-evasion"]
            },
            "T1140": {
                "name": "Deobfuscate/Decode Files or Information",
                "description": "Adversaries may use Obfuscated Files or Information to hide artifacts of an intrusion from analysis.",
                "tactics": ["defense-evasion"]
            },
            "T1012": {
                "name": "Query Registry",
                "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
                "tactics": ["discovery"]
            },
            "T1082": {
                "name": "System Information Discovery",
                "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.",
                "tactics": ["discovery"]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
                "tactics": ["execution"]
            },
            "T1059.001": {
                "name": "Command and Scripting Interpreter: PowerShell",
                "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
                "tactics": ["execution"]
            },
            "T1547": {
                "name": "Boot or Logon Autostart Execution",
                "description": "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges.",
                "tactics": ["persistence", "privilege-escalation"]
            },
            "T1547.001": {
                "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key.",
                "tactics": ["persistence", "privilege-escalation"]
            },
            "T1486": {
                "name": "Data Encrypted for Impact",
                "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
                "tactics": ["impact"]
            },
            "T1083": {
                "name": "File and Directory Discovery",
                "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
                "tactics": ["discovery"]
            },
            "T1496": {
                "name": "Resource Hijacking",
                "description": "Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems which may impact system and/or hosted service availability.",
                "tactics": ["impact"]
            },
            "T1053.005": {
                "name": "Scheduled Task/Job: Scheduled Task",
                "description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.",
                "tactics": ["execution", "persistence", "privilege-escalation"]
            },
            "T1574.001": {
                "name": "Hijack Execution Flow: DLL Search Order Hijacking",
                "description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs.",
                "tactics": ["persistence", "privilege-escalation", "defense-evasion"]
            }
        }
    
    def generate_attack_matrix(self, ttps_data: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Generate MITRE ATT&CK matrix from TTP data.
        
        Args:
            ttps_data: List of TTP mappings from ttp_mapper.map_ttps()
            
        Returns:
            Dictionary organized by tactics containing technique information
        """
        attack_matrix = {}
        
        # Extract all unique technique IDs
        technique_ids = set()
        ttp_dict = {}
        
        for entry in ttps_data:
            signature = entry["signature"]
            for ttp in entry["ttps"]:
                technique_ids.add(ttp)
                ttp_dict.setdefault(ttp, set()).add(signature)
        
        if self.use_online and self.mitre:
            return self._generate_online_matrix(technique_ids, ttp_dict)
        else:
            return self._generate_offline_matrix(technique_ids, ttp_dict)
    
    def _generate_online_matrix(self, technique_ids: set, ttp_dict: Dict[str, set]) -> Dict[str, List[Dict[str, Any]]]:
        """Generate attack matrix using online pyattck data."""
        attack_matrix = {}
        
        try:
            for technique in self.mitre.enterprise.techniques:
                if technique.technique_id not in technique_ids:
                    continue
                
                for tactic in technique.tactics:
                    tactic_name = tactic.name.lower().replace(' ', '-')
                    
                    if tactic_name not in attack_matrix:
                        attack_matrix[tactic_name] = []
                    
                    attack_matrix[tactic_name].append({
                        "technique_id": technique.technique_id,
                        "technique_name": technique.name,
                        "description": technique.description,
                        "signatures": list(ttp_dict[technique.technique_id])
                    })
            
        except Exception as e:
            log.error(f"Error generating online attack matrix: {e}")
            return self._generate_offline_matrix(technique_ids, ttp_dict)
        
        return attack_matrix
    
    def _generate_offline_matrix(self, technique_ids: set, ttp_dict: Dict[str, set]) -> Dict[str, List[Dict[str, Any]]]:
        """Generate attack matrix using offline/embedded data."""
        attack_matrix = {}
        
        for technique_id in technique_ids:
            technique_data = self.enterprise_data.get(technique_id)
            if not technique_data:
                log.warning(f"No data found for technique: {technique_id}")
                continue
            
            for tactic in technique_data["tactics"]:
                if tactic not in attack_matrix:
                    attack_matrix[tactic] = []
                
                attack_matrix[tactic].append({
                    "technique_id": technique_id,
                    "technique_name": technique_data["name"],
                    "description": technique_data["description"],
                    "signatures": list(ttp_dict[technique_id])
                })
        
        return attack_matrix
    
    def export_to_json(self, attack_matrix: Dict[str, List[Dict[str, Any]]], 
                      output_file: str, include_metadata: bool = True) -> None:
        """
        Export attack matrix to JSON file.
        
        Args:
            attack_matrix: Generated attack matrix
            output_file: Output file path
            include_metadata: Whether to include metadata in output
        """
        output_data = {
            "mitre_attack_matrix": attack_matrix
        }
        
        if include_metadata:
            output_data["metadata"] = {
                "version": "1.0",
                "generated_by": "MITRE ATT&CK Standalone Integration",
                "data_source": "online" if self.use_online else "offline",
                "technique_count": sum(len(techniques) for techniques in attack_matrix.values()),
                "tactic_count": len(attack_matrix),
                "tactics": list(attack_matrix.keys())
            }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            log.info(f"MITRE ATT&CK matrix exported to: {output_file}")
            
        except Exception as e:
            log.error(f"Failed to export to JSON: {e}")
    
    def print_matrix_summary(self, attack_matrix: Dict[str, List[Dict[str, Any]]]) -> None:
        """
        Print a summary of the generated attack matrix.
        
        Args:
            attack_matrix: Generated attack matrix
        """
        print(f"\n=== MITRE ATT&CK Matrix Summary ===")
        print(f"Data source: {'Online (pyattck)' if self.use_online else 'Offline (embedded)'}")
        print(f"Total tactics: {len(attack_matrix)}")
        print(f"Total techniques: {sum(len(techniques) for techniques in attack_matrix.values())}")
        
        for tactic, techniques in attack_matrix.items():
            print(f"\n{tactic.upper().replace('-', ' ')} ({len(techniques)} techniques):")
            for technique in techniques:
                signatures_str = ', '.join(technique['signatures'])
                print(f"  • {technique['technique_id']} - {technique['technique_name']}")
                print(f"    Signatures: {signatures_str}")
    
    def get_tactic_coverage(self, attack_matrix: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Get coverage statistics for MITRE ATT&CK tactics.
        
        Args:
            attack_matrix: Generated attack matrix
            
        Returns:
            Dictionary with tactic coverage statistics
        """
        coverage = {}
        total_techniques = sum(len(techniques) for techniques in attack_matrix.values())
        
        for tactic, techniques in attack_matrix.items():
            coverage[tactic] = {
                "technique_count": len(techniques),
                "percentage": (len(techniques) / total_techniques * 100) if total_techniques > 0 else 0,
                "techniques": [t["technique_id"] for t in techniques]
            }
        
        return coverage