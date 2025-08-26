#!/usr/bin/env python3
"""
Conversion Script for Tracee and Traffic Analysis Data to MITRE Standalone Format

This script converts CAPEv2 analysis reports from tracee (eBPF-based Linux analysis) 
and traffic (network analysis) to the format expected by mitre_standalone.py for 
MITRE ATT&CK integration and behavioral analysis.

Usage:
    python convert_to_mitre_standalone.py --tracee tracee.json.analysis.json --traffic traffic.json --output converted_analysis.json
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime


def setup_logging(log_level: str = "INFO") -> None:
    """Setup logging configuration."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def load_json_file(file_path: str) -> Dict[str, Any]:
    """
    Load JSON file and return parsed data.
    
    Args:
        file_path: Path to JSON file
        
    Returns:
        Parsed JSON data as dictionary
        
    Raises:
        FileNotFoundError: If file doesn't exist
        json.JSONDecodeError: If file contains invalid JSON
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Successfully loaded: {file_path}")
        return data
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in {file_path}: {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading {file_path}: {e}")
        raise


def extract_processes_from_tracee(tracee_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract process information from tracee analysis data.
    
    Args:
        tracee_data: Tracee analysis data
        
    Returns:
        List of process dictionaries in mitre_standalone format
    """
    processes = []
    
    # Extract from proctree metadata
    if "metadata" in tracee_data and "proctree" in tracee_data["metadata"]:
        proctree = tracee_data["metadata"]["proctree"]
        
        def extract_from_proctree(node: Dict[str, Any], parent_pid: Optional[int] = None):
            """Recursively extract processes from proctree."""
            if "pid" in node and "details" in node:
                details = node["details"]
                process_name = details.get("processName", "unknown")
                pid = node["pid"]
                
                # Skip the root abstraction process
                if pid != 0 and process_name != "(ABSTRACTION) root process":
                    process = {
                        "process_name": process_name,
                        "command_line": details.get("desc", f"{process_name}"),
                        "pid": pid,
                        "parent_pid": parent_pid
                    }
                    
                    # Add additional metadata if available
                    if "timestamp" in details:
                        process["timestamp"] = details["timestamp"]
                    if "syscall" in details:
                        process["creation_syscall"] = details["syscall"]
                    if "type" in details:
                        process["type"] = details["type"]
                    
                    processes.append(process)
                
                # Process children
                if "children" in node:
                    for child_pid, child_node in node["children"].items():
                        extract_from_proctree(child_node, pid)
        
        extract_from_proctree(proctree)
    
    # Also extract from syscalls for additional process information
    if "syscalls" in tracee_data:
        seen_processes = set()
        for syscall in tracee_data["syscalls"]:
            if "processId" in syscall and "processName" in syscall:
                pid = syscall["processId"]
                process_name = syscall["processName"]
                
                # Avoid duplicates
                if (pid, process_name) not in seen_processes:
                    seen_processes.add((pid, process_name))
                    
                    # Check if we already have this process from proctree
                    existing = False
                    for existing_proc in processes:
                        if existing_proc["pid"] == pid and existing_proc["process_name"] == process_name:
                            existing = True
                            break
                    
                    if not existing:
                        process = {
                            "process_name": process_name,
                            "command_line": syscall.get("executable", {}).get("path", process_name),
                            "pid": pid
                        }
                        
                        if "parentProcessId" in syscall:
                            process["parent_pid"] = syscall["parentProcessId"]
                        if "timestamp" in syscall:
                            process["timestamp"] = syscall["timestamp"]
                        
                        processes.append(process)
    
    logging.info(f"Extracted {len(processes)} processes from tracee data")
    return processes


def extract_file_operations_from_tracee(tracee_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract file operations from tracee syscalls.
    
    Args:
        tracee_data: Tracee analysis data
        
    Returns:
        List of file operation dictionaries in mitre_standalone format
    """
    file_operations = []
    
    if "syscalls" not in tracee_data:
        return file_operations
    
    # Map tracee syscalls to file operations
    file_syscalls = {
        "openat": "open",
        "open": "open", 
        "creat": "create",
        "unlink": "delete",
        "unlinkat": "delete",
        "write": "write",
        "read": "read",
        "rename": "rename",
        "mkdir": "create",
        "rmdir": "delete"
    }
    
    for syscall in tracee_data["syscalls"]:
        event_name = syscall.get("eventName", "")
        
        if event_name in file_syscalls:
            operation_type = file_syscalls[event_name]
            
            # Extract filename from args - more specific handling
            filename = None
            if "args" in syscall and len(syscall["args"]) > 0:
                args = syscall["args"]
                
                if event_name == "openat" and len(args) >= 2:
                    # For openat: args[1] is the pathname
                    filename = str(args[1].get("value", ""))
                elif event_name in ["open", "creat", "unlink", "mkdir", "rmdir"]:
                    # For these syscalls, first argument is usually the path
                    filename = str(args[0].get("value", ""))
                elif event_name == "unlinkat" and len(args) >= 2:
                    # For unlinkat: args[1] is the pathname  
                    filename = str(args[1].get("value", ""))
                else:
                    # Generic approach: find first string argument that looks like a path
                    for arg in args:
                        if arg.get("type") == "const char*" and arg.get("value"):
                            val = str(arg["value"])
                            if val and val != "0x0" and not val.startswith("0x") and ("/" in val or val.startswith(".")):
                                filename = val
                                break
            
            # Filter out invalid or system-internal paths
            if (filename and 
                filename != "0x0" and 
                not filename.startswith("0x") and 
                filename != "-100" and
                len(filename) > 1):
                
                file_op = {
                    "operation": operation_type,
                    "filename": filename,
                    "timestamp": syscall.get("timestamp"),
                    "process_id": syscall.get("processId"),
                    "process_name": syscall.get("processName")
                }
                file_operations.append(file_op)
    
    logging.info(f"Extracted {len(file_operations)} file operations from tracee data")
    return file_operations


def extract_network_from_traffic(traffic_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract network information from traffic analysis data.
    
    Args:
        traffic_data: Traffic analysis data
        
    Returns:
        Network data dictionary in mitre_standalone format
    """
    network = {
        "http": [],
        "dns": [], 
        "tcp": [],
        "udp": []
    }
    
    # Extract HTTP requests
    if "http" in traffic_data:
        for http_req in traffic_data["http"]:
            network["http"].append({
                "uri": http_req.get("uri", "/"),
                "host": http_req.get("host", ""),
                "method": http_req.get("method", "GET"),
                "user_agent": http_req.get("user_agent", ""),
                "src": http_req.get("src", ""),
                "dst": http_req.get("dst", ""),
                "timestamp": http_req.get("timestamp")
            })
    
    # Extract DNS queries
    if "dns" in traffic_data:
        for dns_req in traffic_data["dns"]:
            network["dns"].append({
                "request": dns_req.get("request", ""),
                "type": dns_req.get("type", "A"),
                "timestamp": dns_req.get("timestamp"),
                "answers": dns_req.get("answers", [])
            })
    
    # Extract TCP connections
    if "tcp" in traffic_data:
        for tcp_conn in traffic_data["tcp"]:
            network["tcp"].append({
                "src": tcp_conn.get("src", ""),
                "dst": f"{tcp_conn.get('dst', '')}:{tcp_conn.get('dport', '')}",
                "sport": tcp_conn.get("sport"),
                "dport": tcp_conn.get("dport"),
                "bytes": tcp_conn.get("bytes", 0),
                "timestamp": tcp_conn.get("time")
            })
    
    # Extract UDP connections  
    if "udp" in traffic_data:
        for udp_conn in traffic_data["udp"]:
            network["udp"].append({
                "src": udp_conn.get("src", ""),
                "dst": f"{udp_conn.get('dst', '')}:{udp_conn.get('dport', '')}",
                "sport": udp_conn.get("sport"),
                "dport": udp_conn.get("dport"),
                "bytes": udp_conn.get("bytes", 0),
                "timestamp": udp_conn.get("time")
            })
    
    logging.info(f"Extracted network data: {len(network['http'])} HTTP, {len(network['dns'])} DNS, {len(network['tcp'])} TCP, {len(network['udp'])} UDP")
    return network


def extract_registry_operations_from_tracee(tracee_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract registry-like operations from tracee syscalls.
    
    Note: Linux doesn't have a registry like Windows, but we can extract
    configuration file modifications and system settings changes.
    
    Args:
        tracee_data: Tracee analysis data
        
    Returns:
        List of registry-like operation dictionaries
    """
    registry_operations = []
    
    if "syscalls" not in tracee_data:
        return registry_operations
    
    # Look for modifications to important system configuration files
    config_files = [
        "/etc/", "/proc/sys/", "/sys/", "~/.config/", "~/.bashrc", 
        "~/.profile", "/var/", "/opt/", "/home/"
    ]
    
    for syscall in tracee_data["syscalls"]:
        event_name = syscall.get("eventName", "")
        
        if event_name in ["openat", "write", "writev"] and "args" in syscall:
            # Check if this involves a configuration file
            for arg in syscall["args"]:
                if arg.get("type") == "const char*" and arg.get("value"):
                    path = str(arg["value"])
                    
                    for config_path in config_files:
                        if config_path in path:
                            registry_op = {
                                "operation": "set",
                                "key": path,
                                "value": "modified",
                                "data": f"System configuration modified via {event_name}",
                                "timestamp": syscall.get("timestamp"),
                                "process_id": syscall.get("processId"),
                                "process_name": syscall.get("processName")
                            }
                            registry_operations.append(registry_op)
                            break
    
    logging.info(f"Extracted {len(registry_operations)} registry-like operations from tracee data")
    return registry_operations


def convert_reports_to_mitre_format(tracee_path: str, traffic_path: str) -> Dict[str, Any]:
    """
    Convert tracee and traffic reports to mitre_standalone format.
    
    Args:
        tracee_path: Path to tracee.json.analysis.json
        traffic_path: Path to traffic.json
        
    Returns:
        Dictionary in mitre_standalone expected format
    """
    logging.info("Starting conversion process...")
    
    # Load input files
    tracee_data = load_json_file(tracee_path)
    traffic_data = load_json_file(traffic_path)
    
    # Extract data components
    processes = extract_processes_from_tracee(tracee_data)
    file_operations = extract_file_operations_from_tracee(tracee_data)
    registry_operations = extract_registry_operations_from_tracee(tracee_data)
    network = extract_network_from_traffic(traffic_data)
    
    # Build final structure
    converted_data = {
        "metadata": {
            "conversion_timestamp": datetime.now().isoformat(),
            "source_files": {
                "tracee": tracee_path,
                "traffic": traffic_path
            },
            "converter_version": "1.0.0"
        },
        "processes": processes,
        "network": network,
        "file_operations": file_operations,
        "registry_operations": registry_operations
    }
    
    logging.info("Conversion completed successfully")
    return converted_data


def validate_input_files(tracee_path: str, traffic_path: str) -> bool:
    """
    Validate that input files exist and have expected structure.
    
    Args:
        tracee_path: Path to tracee file
        traffic_path: Path to traffic file
        
    Returns:
        True if files are valid, False otherwise
    """
    errors = []
    
    # Check file existence
    if not os.path.exists(tracee_path):
        errors.append(f"Tracee file not found: {tracee_path}")
    if not os.path.exists(traffic_path):
        errors.append(f"Traffic file not found: {traffic_path}")
    
    if errors:
        for error in errors:
            logging.error(error)
        return False
    
    # Check file structure
    try:
        tracee_data = load_json_file(tracee_path)
        traffic_data = load_json_file(traffic_path)
        
        # Validate tracee structure
        if "syscalls" not in tracee_data and "metadata" not in tracee_data:
            errors.append(f"Invalid tracee file structure: missing 'syscalls' or 'metadata'")
        
        # Validate traffic structure  
        expected_keys = ["tcp", "udp", "http", "dns"]
        if not any(key in traffic_data for key in expected_keys):
            errors.append(f"Invalid traffic file structure: missing network data")
        
    except Exception as e:
        errors.append(f"Error validating input files: {e}")
    
    if errors:
        for error in errors:
            logging.error(error)
        return False
    
    return True


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Convert tracee and traffic analysis data to mitre_standalone format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert reports and save to file
  python convert_to_mitre_standalone.py --tracee report/tracee.json.analysis.json --traffic report/traffic.json --output converted_analysis.json

  # Convert and run mitre_standalone directly  
  python convert_to_mitre_standalone.py --tracee report/tracee.json.analysis.json --traffic report/traffic.json --output converted.json --run-mitre

  # Verbose output for debugging
  python convert_to_mitre_standalone.py --tracee report/tracee.json.analysis.json --traffic report/traffic.json --output converted.json --verbose
        """
    )
    
    parser.add_argument(
        '--tracee', '-t',
        type=str,
        required=True,
        help='Path to tracee.json.analysis.json file'
    )
    
    parser.add_argument(
        '--traffic', '-r', 
        type=str,
        required=True,
        help='Path to traffic.json file'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='converted_analysis.json',
        help='Output file path for converted data (default: converted_analysis.json)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--run-mitre',
        action='store_true', 
        help='Automatically run mitre_standalone.py after conversion'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level)
    
    try:
        # Validate input files
        if not validate_input_files(args.tracee, args.traffic):
            logging.error("Input file validation failed")
            return 1
        
        # Perform conversion
        converted_data = convert_reports_to_mitre_format(args.tracee, args.traffic)
        
        # Save to output file
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(converted_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Converted data saved to: {args.output}")
        
        # Print summary
        print(f"\n=== Conversion Summary ===")
        print(f"Input files:")
        print(f"  - Tracee: {args.tracee}")
        print(f"  - Traffic: {args.traffic}")
        print(f"Output file: {args.output}")
        print(f"Extracted data:")
        print(f"  - Processes: {len(converted_data['processes'])}")
        print(f"  - File operations: {len(converted_data['file_operations'])}")
        print(f"  - Registry operations: {len(converted_data['registry_operations'])}")
        print(f"  - HTTP requests: {len(converted_data['network']['http'])}")
        print(f"  - DNS queries: {len(converted_data['network']['dns'])}")
        print(f"  - TCP connections: {len(converted_data['network']['tcp'])}")
        print(f"  - UDP connections: {len(converted_data['network']['udp'])}")
        
        # Optionally run mitre_standalone
        if args.run_mitre:
            print(f"\n=== Running MITRE Standalone Analysis ===")
            mitre_script = os.path.join(os.path.dirname(__file__), "mitre_standalone", "mitre_standalone.py")
            if os.path.exists(mitre_script):
                import subprocess
                result = subprocess.run([
                    sys.executable, mitre_script, 
                    "--input", args.output,
                    "--output", f"mitre_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    print("MITRE analysis completed successfully!")
                    print(result.stdout)
                else:
                    print("MITRE analysis failed:")
                    print(result.stderr)
            else:
                print(f"MITRE standalone script not found at: {mitre_script}")
        
        return 0
        
    except Exception as e:
        logging.error(f"Conversion failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())