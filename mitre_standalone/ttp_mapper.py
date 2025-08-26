"""
TTP Mapping functionality for grouping TTPs by signature
"""

import logging
from collections import defaultdict
from typing import List, Dict, Any

log = logging.getLogger(__name__)


def map_ttps(ttps_list: List[Dict[str, str]], mbcs_dict: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Maps TTPs (Tactics, Techniques, and Procedures) and groups them by signature.
    
    This function takes a list of individual TTP entries and groups them by signature name,
    removing duplicates and adding associated MBCs (Malware Behavior Catalog) entries.
    
    Args:
        ttps_list: List of dictionaries containing TTP and signature mappings.
                  Each dictionary should have "ttp" and "signature" keys.
                  Example: [{"ttp": "T1071", "signature": "http_request"}, 
                           {"ttp": "T1112", "signature": "modify_proxy"}]
                           
        mbcs_dict: Dictionary mapping signature names to their MBC entries.
                  Example: {"http_request": ["OB0004", "C0002"]}
    
    Returns:
        List of dictionaries where each dictionary contains:
        - "signature" (str): The signature name
        - "ttps" (list): List of unique TTPs associated with the signature
        - "mbcs" (list): List of MBCs associated with the signature
        
        Example output:
        [
            {
                "signature": "http_request",
                "ttps": ["T1071"],
                "mbcs": ["OB0004", "C0002"]
            },
            {
                "signature": "modify_proxy", 
                "ttps": ["T1112"],
                "mbcs": []
            }
        ]
    """
    grouped_ttps = defaultdict(list)
    
    # Group TTPs by signature
    for ttp_entry in ttps_list:
        signature = ttp_entry.get("signature")
        ttp = ttp_entry.get("ttp")
        
        if signature and ttp:
            grouped_ttps[signature].append(ttp)
    
    # Create final result list
    result = []
    for signature, ttps in grouped_ttps.items():
        # Remove duplicates while preserving order
        unique_ttps = list(dict.fromkeys(ttps))
        
        # Get associated MBCs
        signature_mbcs = mbcs_dict.get(signature, [])
        
        result.append({
            "signature": signature,
            "ttps": unique_ttps,
            "mbcs": signature_mbcs
        })
    
    log.info(f"Mapped {len(ttps_list)} TTP entries into {len(result)} signature groups")
    return result


def filter_ttps_by_version(ttps_list: List[Dict[str, Any]], mitre_version: str = "v12") -> List[Dict[str, Any]]:
    """
    Filter TTPs based on MITRE ATT&CK version compatibility.
    
    Some TTPs might not be available in older versions of MITRE ATT&CK.
    This function can be used to filter out incompatible TTPs.
    
    Args:
        ttps_list: List of TTP mappings from map_ttps()
        mitre_version: MITRE ATT&CK version to filter for
        
    Returns:
        Filtered list of TTP mappings
    """
    # For now, just return the original list
    # This could be enhanced with actual version checking logic
    log.debug(f"Filtering TTPs for MITRE ATT&CK version: {mitre_version}")
    return ttps_list


def get_unique_techniques(ttps_list: List[Dict[str, Any]]) -> List[str]:
    """
    Extract all unique technique IDs from TTP mappings.
    
    Args:
        ttps_list: List of TTP mappings from map_ttps()
        
    Returns:
        List of unique technique IDs
    """
    all_ttps = []
    for entry in ttps_list:
        all_ttps.extend(entry.get("ttps", []))
    
    unique_ttps = list(dict.fromkeys(all_ttps))
    log.debug(f"Found {len(unique_ttps)} unique techniques")
    return unique_ttps


def get_signature_coverage(ttps_list: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Get coverage statistics for signatures and their TTPs.
    
    Args:
        ttps_list: List of TTP mappings from map_ttps()
        
    Returns:
        Dictionary with signature coverage statistics
    """
    coverage = {}
    total_techniques = len(get_unique_techniques(ttps_list))
    
    for entry in ttps_list:
        signature = entry["signature"]
        signature_ttps = entry["ttps"]
        signature_mbcs = entry["mbcs"]
        
        coverage[signature] = {
            "technique_count": len(signature_ttps),
            "techniques": signature_ttps,
            "mbc_count": len(signature_mbcs),
            "mbcs": signature_mbcs,
            "coverage_percentage": (len(signature_ttps) / total_techniques * 100) if total_techniques > 0 else 0
        }
    
    return coverage


def print_ttp_summary(ttps_list: List[Dict[str, Any]]) -> None:
    """
    Print a summary of TTP mappings.
    
    Args:
        ttps_list: List of TTP mappings from map_ttps()
    """
    print(f"\n=== TTP Mapping Summary ===")
    print(f"Total signature groups: {len(ttps_list)}")
    
    unique_techniques = get_unique_techniques(ttps_list)
    print(f"Unique techniques: {len(unique_techniques)}")
    
    print(f"\nSignature Coverage:")
    for entry in ttps_list:
        signature = entry["signature"]
        ttps = entry["ttps"]
        mbcs = entry["mbcs"]
        
        print(f"  {signature}:")
        print(f"    TTPs: {', '.join(ttps) if ttps else 'None'}")
        if mbcs:
            print(f"    MBCs: {', '.join(mbcs)}")
    
    if unique_techniques:
        print(f"\nAll Techniques: {', '.join(sorted(unique_techniques))}")


# Legacy TTP mapping data (simplified version of CAPEv2's TTPs.json)
DEFAULT_TTP_MAPPINGS = {
    # Command and Control
    "T1071": "T1071.001",  # Application Layer Protocol: Web Protocols
    "T1095": "T1095",      # Non-Application Layer Protocol
    "T1105": "T1105",      # Ingress Tool Transfer
    
    # Defense Evasion  
    "T1027": "T1027.002",  # Obfuscated Files or Information: Software Packing
    "T1055": "T1055.001",  # Process Injection: Dynamic-link Library Injection
    "T1112": "T1112",      # Modify Registry
    "T1140": "T1140",      # Deobfuscate/Decode Files or Information
    
    # Discovery
    "T1012": "T1012",      # Query Registry
    "T1016": "T1016",      # System Network Configuration Discovery
    "T1082": "T1082",      # System Information Discovery
    
    # Execution
    "T1059": "T1059.001",  # Command and Scripting Interpreter: PowerShell
    "T1106": "T1106",      # Native API
    
    # Persistence
    "T1547": "T1547.001",  # Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
}


def normalize_ttp_id(ttp_id: str) -> str:
    """
    Normalize TTP ID using default mappings.
    
    Args:
        ttp_id: Original TTP ID
        
    Returns:
        Normalized TTP ID
    """
    return DEFAULT_TTP_MAPPINGS.get(ttp_id, ttp_id)