"""
Sample signatures for testing the standalone MITRE ATT&CK integration
"""

from signature_base import ProcessSignature, NetworkSignature, FileSignature, RegistrySignature


class PowerShellExecution(ProcessSignature):
    """Detects PowerShell execution with suspicious parameters."""
    
    name = "powershell_execution"
    description = "Detects PowerShell execution with bypass parameters"
    severity = 3
    confidence = 90
    weight = 2
    categories = ["execution", "bypass"]
    authors = ["CAPE Developers"]
    ttps = ["T1059.001"]  # Command and Scripting Interpreter: PowerShell
    mbcs = ["OB0009", "E1059"]
    
    def run(self) -> bool:
        """Check for PowerShell execution with suspicious parameters."""
        if self.check_process_name("powershell.exe"):
            # Check for execution policy bypass
            if self.check_command_line("-ExecutionPolicy Bypass", regex=False):
                self.add_match("PowerShell executed with ExecutionPolicy Bypass")
                return True
            
            # Check for encoded commands
            if self.check_command_line("-EncodedCommand", regex=False):
                self.add_match("PowerShell executed with encoded command")
                return True
            
            # Check for hidden window
            if self.check_command_line("-WindowStyle Hidden", regex=False):
                self.add_match("PowerShell executed with hidden window")
                return True
        
        return False


class SuspiciousHttpRequest(NetworkSignature):
    """Detects HTTP requests to suspicious domains."""
    
    name = "suspicious_http_request"
    description = "Detects HTTP requests to known malicious domains"
    severity = 2
    confidence = 80
    weight = 1
    categories = ["network", "c2"]
    authors = ["CAPE Developers"]
    ttps = ["T1071.001"]  # Application Layer Protocol: Web Protocols
    mbcs = ["B0030", "C0002"]
    
    def run(self) -> bool:
        """Check for HTTP requests to suspicious domains."""
        suspicious_domains = [
            "malicious-domain.com",
            "evil-server.net",
            "badactor.org"
        ]
        
        for domain in suspicious_domains:
            if self.check_http_request(domain, regex=False):
                self.add_match(f"HTTP request to suspicious domain: {domain}")
                return True
        
        # Check for suspicious file downloads
        if self.check_http_request(r"\.exe$", regex=True):
            self.add_match("HTTP request to download executable file")
            return True
        
        return False


class PersistenceRegistryKey(RegistrySignature):
    """Detects persistence via registry run keys."""
    
    name = "persistence_registry_key"
    description = "Detects persistence mechanism via registry run keys"
    severity = 3
    confidence = 95
    weight = 3
    categories = ["persistence"]
    authors = ["CAPE Developers"]
    ttps = ["T1547.001"]  # Boot or Logon Autostart Execution: Registry Run Keys
    mbcs = ["F0012", "E1547"]
    
    def run(self) -> bool:
        """Check for persistence via registry run keys."""
        run_key_patterns = [
            r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            r"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
        ]
        
        for pattern in run_key_patterns:
            if self.check_registry_key(pattern, regex=True):
                self.add_match(f"Registry persistence key modified: {pattern}")
                return True
        
        return False


class RegistryModification(RegistrySignature):
    """Detects general registry modifications."""
    
    name = "registry_modification"
    description = "Detects modifications to Windows registry"
    severity = 2
    confidence = 70
    weight = 1
    categories = ["modification"]
    authors = ["CAPE Developers"]
    ttps = ["T1112"]  # Modify Registry
    mbcs = ["E1112"]
    
    def run(self) -> bool:
        """Check for registry modifications."""
        # Check for any registry modifications (very broad detection)
        registry_ops = self.analysis_data.get("registry_operations", [])
        if registry_ops:
            for operation in registry_ops:
                if operation.get("operation") in ["set", "create", "modify"]:
                    key_name = operation.get("key", "")
                    self.add_match(f"Registry key modified: {key_name}")
                    return True
        
        return False


class MaliciousFileCreation(FileSignature):
    """Detects creation of suspicious files."""
    
    name = "malicious_file_creation"
    description = "Detects creation of files in suspicious locations"
    severity = 2
    confidence = 75
    weight = 2
    categories = ["file", "persistence"]
    authors = ["CAPE Developers"]
    ttps = ["T1027.002"]  # Obfuscated Files or Information: Software Packing
    mbcs = ["F0001", "OB0006"]
    
    def run(self) -> bool:
        """Check for creation of suspicious files."""
        suspicious_patterns = [
            r"\\temp\\.*\.exe$",
            r"\\AppData\\Roaming\\.*\.bat$",
            r"\\AppData\\Local\\.*\.exe$",
            r"\\Users\\.*\\Desktop\\.*\.scr$"
        ]
        
        for pattern in suspicious_patterns:
            if self.check_file_created(pattern, regex=True):
                self.add_match(f"Suspicious file created matching pattern: {pattern}")
                return True
        
        return False


class SystemDiscovery(ProcessSignature):
    """Detects system discovery commands."""
    
    name = "system_discovery"
    description = "Detects system information discovery commands"
    severity = 1
    confidence = 60
    weight = 1
    categories = ["discovery"]
    authors = ["CAPE Developers"]
    ttps = ["T1082"]  # System Information Discovery
    mbcs = ["E1082"]
    
    def run(self) -> bool:
        """Check for system discovery commands."""
        discovery_commands = [
            "whoami",
            "systeminfo",
            "ipconfig",
            "net user",
            "net group"
        ]
        
        for command in discovery_commands:
            if self.check_command_line(command, regex=False):
                self.add_match(f"System discovery command executed: {command}")
                return True
        
        return False


class DNSQuery(NetworkSignature):
    """Detects DNS queries to suspicious domains."""
    
    name = "dns_query"
    description = "Detects DNS queries to suspicious domains"
    severity = 1
    confidence = 50
    weight = 1
    categories = ["network", "discovery"]
    authors = ["CAPE Developers"]
    ttps = ["T1012"]  # Query Registry (using as discovery technique)
    mbcs = ["B0007"]
    
    def run(self) -> bool:
        """Check for DNS queries to suspicious domains."""
        if self.check_dns_query("malicious-domain.com"):
            self.add_match("DNS query to malicious domain")
            return True
        
        return False