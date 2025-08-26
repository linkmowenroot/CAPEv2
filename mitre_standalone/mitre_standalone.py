#!/usr/bin/env python3
"""
Standalone MITRE ATT&CK Integration Module
Main execution script for processing behavioral analysis data and generating MITRE ATT&CK reports.
"""

import argparse
import json
import logging
import os
import sys
from typing import Dict, Any, Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from signature_engine import SignatureEngine, create_sample_analysis_data
from ttp_mapper import map_ttps, print_ttp_summary, get_signature_coverage
from mitre_integration import MitreAttackIntegration


def setup_logging(log_level: str = "INFO") -> None:
    """Setup logging configuration."""
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def load_analysis_data(file_path: str) -> Dict[str, Any]:
    """
    Load analysis data from JSON file.
    
    Args:
        file_path: Path to JSON file containing analysis data
        
    Returns:
        Dictionary containing analysis data
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        logging.info(f"Loaded analysis data from: {file_path}")
        return data
    except Exception as e:
        logging.error(f"Failed to load analysis data from {file_path}: {e}")
        raise


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Standalone MITRE ATT&CK Integration for Behavioral Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with sample data
  python mitre_standalone.py --sample

  # Process analysis data from JSON file
  python mitre_standalone.py --input analysis_data.json

  # Use online MITRE data (requires pyattck)
  python mitre_standalone.py --sample --online

  # Save results to specific file
  python mitre_standalone.py --sample --output results.json

  # Load custom signatures
  python mitre_standalone.py --sample --signatures ./custom_signatures/

  # Verbose output
  python mitre_standalone.py --sample --verbose
        """
    )
    
    # Input options
    parser.add_argument(
        '--input', '-i',
        type=str,
        help='Path to JSON file containing analysis data'
    )
    
    parser.add_argument(
        '--sample', '-s',
        action='store_true',
        help='Use sample analysis data for testing'
    )
    
    # Output options
    parser.add_argument(
        '--output', '-o',
        type=str,
        default='mitre_attack_results.json',
        help='Output file path for MITRE ATT&CK results (default: mitre_attack_results.json)'
    )
    
    # Signature options
    parser.add_argument(
        '--signatures', '-sig',
        type=str,
        help='Path to directory containing signature files'
    )
    
    # MITRE options
    parser.add_argument(
        '--online',
        action='store_true',
        help='Use online MITRE ATT&CK data (requires pyattck library)'
    )
    
    # Other options
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--no-metadata',
        action='store_true',
        help='Exclude metadata from JSON output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logging(log_level)
    
    logging.info("Starting MITRE ATT&CK Standalone Integration")
    
    try:
        # Load analysis data
        if args.input:
            analysis_data = load_analysis_data(args.input)
        elif args.sample:
            logging.info("Using sample analysis data")
            analysis_data = create_sample_analysis_data()
        else:
            logging.error("No input specified. Use --input or --sample")
            return 1
        
        # Initialize signature engine
        logging.info("Initializing signature engine...")
        engine = SignatureEngine()
        
        # Load signatures
        if args.signatures:
            logging.info(f"Loading signatures from: {args.signatures}")
            engine.load_signatures_from_directory(args.signatures)
        else:
            # Load sample signatures
            logging.info("Loading sample signatures...")
            from sample_signatures import (
                PowerShellExecution, SuspiciousHttpRequest, PersistenceRegistryKey,
                RegistryModification, MaliciousFileCreation, SystemDiscovery, DNSQuery
            )
            
            sample_signatures = [
                PowerShellExecution, SuspiciousHttpRequest, PersistenceRegistryKey,
                RegistryModification, MaliciousFileCreation, SystemDiscovery, DNSQuery
            ]
            
            for sig_class in sample_signatures:
                engine.add_signature_class(sig_class)
        
        # Run signatures
        logging.info("Running signatures against analysis data...")
        matched_signatures = engine.run_signatures(analysis_data)
        
        # Print signature results
        engine.print_results()
        
        # Map TTPs
        logging.info("Mapping TTPs...")
        ttps_data = map_ttps(engine.get_ttps(), engine.get_mbcs())
        print_ttp_summary(ttps_data)
        
        # Initialize MITRE integration
        logging.info("Initializing MITRE ATT&CK integration...")
        mitre = MitreAttackIntegration(use_online=args.online)
        
        # Generate attack matrix
        logging.info("Generating MITRE ATT&CK matrix...")
        attack_matrix = mitre.generate_attack_matrix(ttps_data)
        
        # Print matrix summary
        mitre.print_matrix_summary(attack_matrix)
        
        # Export to JSON
        logging.info(f"Exporting results to: {args.output}")
        include_metadata = not args.no_metadata
        mitre.export_to_json(attack_matrix, args.output, include_metadata)
        
        # Print final summary
        print(f"\n=== Final Summary ===")
        print(f"Analysis completed successfully!")
        print(f"- Signatures processed: {len(engine.signatures)}")
        print(f"- Signatures matched: {len(matched_signatures)}")
        print(f"- TTPs extracted: {len(engine.get_ttps())}")
        print(f"- MITRE tactics covered: {len(attack_matrix)}")
        print(f"- Results exported to: {args.output}")
        
        logging.info("MITRE ATT&CK integration completed successfully")
        return 0
        
    except Exception as e:
        logging.error(f"Error during execution: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())