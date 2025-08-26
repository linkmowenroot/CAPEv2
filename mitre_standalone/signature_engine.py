"""
Signature Engine for processing signatures and extracting TTPs
"""

import logging
import importlib.util
import inspect
import os
from typing import List, Dict, Any, Optional, Type
from signature_base import Signature

log = logging.getLogger(__name__)


class SignatureEngine:
    """Engine for loading, executing, and processing behavioral signatures."""
    
    def __init__(self, signature_paths: Optional[List[str]] = None):
        """
        Initialize the signature engine.
        
        Args:
            signature_paths: List of paths to search for signature files
        """
        self.signature_paths = signature_paths or []
        self.signatures: List[Type[Signature]] = []
        self.matched_signatures: List[Dict[str, Any]] = []
        self.ttps: List[Dict[str, str]] = []
        self.mbcs: Dict[str, List[str]] = {}
        
    def load_signatures_from_directory(self, directory: str) -> None:
        """
        Load all signature classes from Python files in a directory.
        
        Args:
            directory: Directory path to scan for signature files
        """
        if not os.path.exists(directory):
            log.warning(f"Signature directory does not exist: {directory}")
            return
            
        for filename in os.listdir(directory):
            if filename.endswith('.py') and not filename.startswith('__'):
                filepath = os.path.join(directory, filename)
                self.load_signatures_from_file(filepath)
    
    def load_signatures_from_file(self, filepath: str) -> None:
        """
        Load signature classes from a specific Python file.
        
        Args:
            filepath: Path to the Python file containing signatures
        """
        try:
            spec = importlib.util.spec_from_file_location("signature_module", filepath)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Find all Signature subclasses in the module
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, Signature) and 
                        obj != Signature and
                        hasattr(obj, 'name') and obj.name):
                        
                        self.signatures.append(obj)
                        log.debug(f"Loaded signature: {obj.name}")
                        
        except Exception as e:
            log.error(f"Failed to load signatures from {filepath}: {e}")
    
    def add_signature_class(self, signature_class: Type[Signature]) -> None:
        """
        Add a signature class directly to the engine.
        
        Args:
            signature_class: Signature class to add
        """
        if (issubclass(signature_class, Signature) and 
            hasattr(signature_class, 'name') and signature_class.name):
            self.signatures.append(signature_class)
            log.debug(f"Added signature: {signature_class.name}")
        else:
            log.warning(f"Invalid signature class: {signature_class}")
    
    def run_signatures(self, analysis_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Execute all loaded signatures against analysis data.
        
        Args:
            analysis_data: Dictionary containing analysis results and behavioral data
            
        Returns:
            List of matched signature results
        """
        self.matched_signatures = []
        self.ttps = []
        self.mbcs = {}
        
        log.info(f"Running {len(self.signatures)} signatures...")
        
        for signature_class in self.signatures:
            try:
                # Skip disabled signatures
                if hasattr(signature_class, 'enabled') and not signature_class.enabled:
                    continue
                
                # Initialize signature with analysis data
                signature_instance = signature_class(analysis_data)
                
                # Run the signature
                log.debug(f"Running signature: {signature_instance.name}")
                matched = signature_instance.run()
                
                if matched:
                    signature_instance.matched = True
                    result = signature_instance.as_result()
                    self.matched_signatures.append(result)
                    
                    # Extract TTPs
                    if hasattr(signature_instance, 'ttps') and signature_instance.ttps:
                        for ttp in signature_instance.ttps:
                            self.ttps.append({
                                "ttp": ttp,
                                "signature": signature_instance.name
                            })
                    
                    # Extract MBCs
                    if hasattr(signature_instance, 'mbcs') and signature_instance.mbcs:
                        self.mbcs[signature_instance.name] = signature_instance.mbcs
                    
                    log.info(f"Signature matched: {signature_instance.name}")
                else:
                    log.debug(f"Signature not matched: {signature_instance.name}")
                    
            except Exception as e:
                log.error(f"Error running signature {signature_class.name}: {e}")
        
        log.info(f"Matched {len(self.matched_signatures)} signatures")
        return self.matched_signatures
    
    def get_ttps(self) -> List[Dict[str, str]]:
        """
        Get extracted TTPs from matched signatures.
        
        Returns:
            List of TTP dictionaries with signature associations
        """
        return self.ttps
    
    def get_mbcs(self) -> Dict[str, List[str]]:
        """
        Get extracted MBCs from matched signatures.
        
        Returns:
            Dictionary of MBCs mapped by signature name
        """
        return self.mbcs
    
    def get_matched_signatures(self) -> List[Dict[str, Any]]:
        """
        Get all matched signature results.
        
        Returns:
            List of matched signature result dictionaries
        """
        return self.matched_signatures
    
    def print_results(self) -> None:
        """Print a summary of signature execution results."""
        print(f"\n=== Signature Execution Results ===")
        print(f"Total signatures loaded: {len(self.signatures)}")
        print(f"Signatures matched: {len(self.matched_signatures)}")
        print(f"TTPs extracted: {len(self.ttps)}")
        
        if self.matched_signatures:
            print(f"\nMatched Signatures:")
            for sig in self.matched_signatures:
                print(f"  - {sig['name']}: {sig['description']}")
                if sig['ttps']:
                    print(f"    TTPs: {', '.join(sig['ttps'])}")
        
        if self.ttps:
            print(f"\nExtracted TTPs:")
            for ttp in self.ttps:
                print(f"  - {ttp['ttp']} (from {ttp['signature']})")


def create_sample_analysis_data() -> Dict[str, Any]:
    """
    Create sample analysis data for testing purposes.
    
    Returns:
        Dictionary containing sample analysis data
    """
    return {
        "processes": [
            {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -ExecutionPolicy Bypass -File malicious.ps1",
                "pid": 1234
            },
            {
                "process_name": "cmd.exe", 
                "command_line": "cmd.exe /c whoami",
                "pid": 5678
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
                    "request": "malicious-domain.com",
                    "type": "A"
                }
            ]
        },
        "file_operations": [
            {
                "operation": "create",
                "filename": "C:\\temp\\malware.exe"
            },
            {
                "operation": "write",
                "filename": "C:\\Users\\user\\AppData\\Roaming\\persistence.bat"
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