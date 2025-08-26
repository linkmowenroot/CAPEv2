"""
Standalone Signature Base Class for MITRE ATT&CK Integration
"""

import logging
from typing import List, Dict, Any, Optional

log = logging.getLogger(__name__)


class Signature:
    """Base class for malware behavior signatures with MITRE ATT&CK integration."""
    
    # Signature metadata
    name: str = ""
    description: str = ""
    severity: int = 1
    confidence: int = 100
    weight: int = 1
    categories: List[str] = []
    families: List[str] = []
    authors: List[str] = []
    references: List[str] = []
    enabled: bool = True
    
    # MITRE ATT&CK TTPs (Tactics, Techniques, and Procedures)
    ttps: List[str] = []
    
    # MBCs (Malware Behavior Catalog) - optional
    mbcs: List[str] = []
    
    def __init__(self, analysis_data: Optional[Dict[str, Any]] = None):
        """
        Initialize signature with analysis data.
        
        Args:
            analysis_data: Dictionary containing analysis results and behavioral data
        """
        self.analysis_data = analysis_data or {}
        self.matched = False
        self.match_data = []
        
    def run(self) -> bool:
        """
        Main signature execution method. Should be overridden by specific signatures.
        
        Returns:
            bool: True if signature matches, False otherwise
        """
        raise NotImplementedError("Subclasses must implement the run() method")
    
    def add_match(self, description: str, **kwargs) -> None:
        """
        Add match data for this signature.
        
        Args:
            description: Description of what was matched
            **kwargs: Additional match metadata
        """
        match_entry = {
            "description": description,
            **kwargs
        }
        self.match_data.append(match_entry)
    
    def as_result(self) -> Dict[str, Any]:
        """
        Convert signature result to dictionary format.
        
        Returns:
            Dictionary representation of signature result
        """
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "weight": self.weight,
            "categories": self.categories,
            "families": self.families,
            "authors": self.authors,
            "references": self.references,
            "ttps": self.ttps,
            "mbcs": self.mbcs,
            "matched": self.matched,
            "match_data": self.match_data
        }


class ProcessSignature(Signature):
    """Base class for process-based signatures."""
    
    def check_process_name(self, process_name: str) -> bool:
        """
        Check if a specific process name exists in the analysis data.
        
        Args:
            process_name: Name of the process to check
            
        Returns:
            bool: True if process found
        """
        processes = self.analysis_data.get("processes", [])
        for process in processes:
            if process.get("process_name", "").lower() == process_name.lower():
                return True
        return False
    
    def check_command_line(self, pattern: str, regex: bool = False) -> bool:
        """
        Check for command line patterns in process data.
        
        Args:
            pattern: Pattern to search for
            regex: Whether to use regex matching
            
        Returns:
            bool: True if pattern found
        """
        import re
        
        processes = self.analysis_data.get("processes", [])
        for process in processes:
            cmdline = process.get("command_line", "")
            if regex:
                if re.search(pattern, cmdline, re.IGNORECASE):
                    return True
            else:
                if pattern.lower() in cmdline.lower():
                    return True
        return False


class NetworkSignature(Signature):
    """Base class for network-based signatures."""
    
    def check_http_request(self, pattern: str, regex: bool = False) -> bool:
        """
        Check for HTTP request patterns.
        
        Args:
            pattern: Pattern to search for
            regex: Whether to use regex matching
            
        Returns:
            bool: True if pattern found
        """
        import re
        
        network_data = self.analysis_data.get("network", {})
        http_requests = network_data.get("http", [])
        
        for request in http_requests:
            url = request.get("uri", "")
            host = request.get("host", "")
            combined = f"{host}{url}"
            
            if regex:
                if re.search(pattern, combined, re.IGNORECASE):
                    return True
            else:
                if pattern.lower() in combined.lower():
                    return True
        return False
    
    def check_dns_query(self, domain: str) -> bool:
        """
        Check for DNS queries to specific domain.
        
        Args:
            domain: Domain to check for
            
        Returns:
            bool: True if domain found in DNS queries
        """
        network_data = self.analysis_data.get("network", {})
        dns_queries = network_data.get("dns", [])
        
        for query in dns_queries:
            if domain.lower() in query.get("request", "").lower():
                return True
        return False


class FileSignature(Signature):
    """Base class for file-based signatures."""
    
    def check_file_created(self, pattern: str, regex: bool = False) -> bool:
        """
        Check for file creation patterns.
        
        Args:
            pattern: Pattern to search for
            regex: Whether to use regex matching
            
        Returns:
            bool: True if pattern found
        """
        import re
        
        file_operations = self.analysis_data.get("file_operations", [])
        for operation in file_operations:
            if operation.get("operation") == "create":
                filename = operation.get("filename", "")
                if regex:
                    if re.search(pattern, filename, re.IGNORECASE):
                        return True
                else:
                    if pattern.lower() in filename.lower():
                        return True
        return False
    
    def check_file_written(self, pattern: str, regex: bool = False) -> bool:
        """
        Check for file write patterns.
        
        Args:
            pattern: Pattern to search for
            regex: Whether to use regex matching
            
        Returns:
            bool: True if pattern found
        """
        import re
        
        file_operations = self.analysis_data.get("file_operations", [])
        for operation in file_operations:
            if operation.get("operation") == "write":
                filename = operation.get("filename", "")
                if regex:
                    if re.search(pattern, filename, re.IGNORECASE):
                        return True
                else:
                    if pattern.lower() in filename.lower():
                        return True
        return False


class RegistrySignature(Signature):
    """Base class for registry-based signatures."""
    
    def check_registry_key(self, pattern: str, regex: bool = False) -> bool:
        """
        Check for registry key patterns.
        
        Args:
            pattern: Pattern to search for
            regex: Whether to use regex matching
            
        Returns:
            bool: True if pattern found
        """
        import re
        
        registry_operations = self.analysis_data.get("registry_operations", [])
        for operation in registry_operations:
            key_name = operation.get("key", "")
            if regex:
                if re.search(pattern, key_name, re.IGNORECASE):
                    return True
            else:
                if pattern.lower() in key_name.lower():
                    return True
        return False
    
    def check_registry_value(self, key_pattern: str, value_pattern: str, regex: bool = False) -> bool:
        """
        Check for registry value patterns.
        
        Args:
            key_pattern: Registry key pattern to search for
            value_pattern: Registry value pattern to search for
            regex: Whether to use regex matching
            
        Returns:
            bool: True if pattern found
        """
        import re
        
        registry_operations = self.analysis_data.get("registry_operations", [])
        for operation in registry_operations:
            key_name = operation.get("key", "")
            value_name = operation.get("value", "")
            value_data = operation.get("data", "")
            
            key_match = False
            value_match = False
            
            if regex:
                key_match = re.search(key_pattern, key_name, re.IGNORECASE)
                value_match = re.search(value_pattern, f"{value_name} {value_data}", re.IGNORECASE)
            else:
                key_match = key_pattern.lower() in key_name.lower()
                value_match = value_pattern.lower() in f"{value_name} {value_data}".lower()
            
            if key_match and value_match:
                return True
        return False