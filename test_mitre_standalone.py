#!/usr/bin/env python3
"""
Simple test script to validate the standalone MITRE ATT&CK integration module.
"""

import json
import os
import sys
import tempfile

# Add the standalone module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mitre_standalone'))

def test_basic_functionality():
    """Test basic functionality of the standalone module."""
    print("Testing basic functionality...")
    
    from signature_engine import SignatureEngine, create_sample_analysis_data
    from ttp_mapper import map_ttps
    from mitre_integration import MitreAttackIntegration
    from sample_signatures import PowerShellExecution, SuspiciousHttpRequest
    
    # Test 1: Create sample data
    print("  ✓ Creating sample analysis data")
    analysis_data = create_sample_analysis_data()
    assert "processes" in analysis_data
    assert "network" in analysis_data
    
    # Test 2: Initialize signature engine
    print("  ✓ Initializing signature engine")
    engine = SignatureEngine()
    engine.add_signature_class(PowerShellExecution)
    engine.add_signature_class(SuspiciousHttpRequest)
    assert len(engine.signatures) == 2
    
    # Test 3: Run signatures
    print("  ✓ Running signatures")
    matched = engine.run_signatures(analysis_data)
    assert len(matched) >= 1  # Should match at least one signature
    assert len(engine.get_ttps()) >= 1  # Should extract at least one TTP
    
    # Test 4: Map TTPs
    print("  ✓ Mapping TTPs")
    ttps_data = map_ttps(engine.get_ttps(), engine.get_mbcs())
    assert len(ttps_data) >= 1
    assert "signature" in ttps_data[0]
    assert "ttps" in ttps_data[0]
    
    # Test 5: Generate MITRE matrix
    print("  ✓ Generating MITRE matrix")
    mitre = MitreAttackIntegration(use_online=False)
    attack_matrix = mitre.generate_attack_matrix(ttps_data)
    assert len(attack_matrix) >= 1  # Should have at least one tactic
    
    # Test 6: Export to JSON
    print("  ✓ Exporting to JSON")
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_file = f.name
    
    try:
        mitre.export_to_json(attack_matrix, output_file)
        assert os.path.exists(output_file)
        
        # Validate JSON structure
        with open(output_file, 'r') as f:
            data = json.load(f)
        assert "mitre_attack_matrix" in data
        assert "metadata" in data
        
    finally:
        os.unlink(output_file)
    
    print("  ✓ All basic functionality tests passed!")


def test_custom_signatures():
    """Test custom signature creation and execution."""
    print("Testing custom signatures...")
    
    from signature_base import ProcessSignature
    from signature_engine import SignatureEngine
    
    # Create a custom signature
    class TestSignature(ProcessSignature):
        name = "test_signature"
        description = "Test signature for validation"
        ttps = ["T1059.001"]
        
        def run(self):
            if self.check_process_name("powershell.exe"):
                self.add_match("Test match")
                return True
            return False
    
    # Test with custom signature
    print("  ✓ Creating custom signature")
    engine = SignatureEngine()
    engine.add_signature_class(TestSignature)
    
    # Create test data
    test_data = {
        "processes": [
            {"process_name": "powershell.exe", "command_line": "test", "pid": 123}
        ],
        "network": {"http": [], "dns": []},
        "file_operations": [],
        "registry_operations": []
    }
    
    print("  ✓ Running custom signature")
    matched = engine.run_signatures(test_data)
    assert len(matched) == 1
    assert matched[0]["name"] == "test_signature"
    assert "T1059.001" in matched[0]["ttps"]
    
    print("  ✓ Custom signature tests passed!")


def test_json_io():
    """Test JSON input/output functionality."""
    print("Testing JSON I/O...")
    
    from signature_engine import create_sample_analysis_data
    
    # Test JSON serialization/deserialization
    print("  ✓ Testing JSON serialization")
    original_data = create_sample_analysis_data()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(original_data, f, indent=2)
        temp_file = f.name
    
    try:
        with open(temp_file, 'r') as f:
            loaded_data = json.load(f)
        
        assert loaded_data == original_data
        print("  ✓ JSON I/O tests passed!")
        
    finally:
        os.unlink(temp_file)


def test_error_handling():
    """Test error handling and edge cases."""
    print("Testing error handling...")
    
    from signature_engine import SignatureEngine
    from mitre_integration import MitreAttackIntegration
    
    # Test empty data
    print("  ✓ Testing empty analysis data")
    engine = SignatureEngine()
    empty_data = {"processes": [], "network": {"http": [], "dns": []}, "file_operations": [], "registry_operations": []}
    matched = engine.run_signatures(empty_data)
    assert len(matched) == 0
    
    # Test MITRE integration with no data
    print("  ✓ Testing MITRE integration with empty data")
    mitre = MitreAttackIntegration(use_online=False)
    empty_matrix = mitre.generate_attack_matrix([])
    assert len(empty_matrix) == 0
    
    print("  ✓ Error handling tests passed!")


def main():
    """Run all tests."""
    print("=== Standalone MITRE ATT&CK Module Validation ===\n")
    
    try:
        test_basic_functionality()
        print()
        
        test_custom_signatures()
        print()
        
        test_json_io()
        print()
        
        test_error_handling()
        print()
        
        print("🎉 All tests passed! The standalone module is working correctly.")
        return 0
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())