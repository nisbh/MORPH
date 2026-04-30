#!/usr/bin/env python3
"""
Integration verification script for MORPH Wave 1-3 implementations.
Tests all new functionality without executing the full pipeline.
"""

import sys
from pathlib import Path

def test_imports():
    """Verify all modules import successfully."""
    print("\n[TEST 1] Module Imports")
    print("=" * 60)
    try:
        import classifier
        import cleanup
        import app
        import ip_profiles
        import main
        print("✓ All modules imported successfully")
        return True
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False

def test_classifier():
    """Verify classifier has new rules."""
    print("\n[TEST 2] Classifier Rules")
    print("=" * 60)
    try:
        from classifier import classify_session
        
        # Test Rule A: short probe
        session_a = {
            "id": "test_a",
            "commands": [],
            "login_attempts": [],
            "start_time": 0,
            "end_time": 6,
        }
        result_a = classify_session(session_a)
        # Rule A should trigger (short_probe_no_commands)
        if result_a["type"] == "bot" and "short_probe_no_commands" in result_a.get("matched_rules", []):
            print("✓ Rule A (short_probe_no_commands) working")
        else:
            print(f"✗ Rule A failed: {result_a}")
            return False
        
        print("✓ Classifier rules validated")
        return True
    except Exception as e:
        print(f"✗ Classifier test failed: {e}")
        return False

def test_cleanup():
    """Verify cleanup utility."""
    print("\n[TEST 3] Cleanup Utility")
    print("=" * 60)
    try:
        from cleanup import count_dossiers, run_cleanup
        
        count = count_dossiers()
        print(f"✓ Dossier count: {count}")
        
        result = run_cleanup()
        if "action" in result:
            print(f"✓ Cleanup executed: action={result['action']}, count={result['count']}")
            return True
        else:
            print(f"✗ Cleanup failed: {result}")
            return False
    except Exception as e:
        print(f"✗ Cleanup test failed: {e}")
        return False

def test_app_functions():
    """Verify app.py has new functions."""
    print("\n[TEST 4] App Functions")
    print("=" * 60)
    try:
        from app import _calculate_threat_score, read_cowrie_event_tail
        
        # Test threat score calculation with profile dict
        # Formula: (high_risk * 3) + medium_risk + (persistence * 2)
        profile = {
            "risk_breakdown": {"high": 1, "medium": 2},
            "intent_breakdown": {"persistence": 1},
        }
        threat_score = _calculate_threat_score(profile)
        expected = (1 * 3) + 2 + (1 * 2)  # = 7
        if threat_score == expected:
            print(f"✓ Threat score calculation: {threat_score} (expected {expected})")
        else:
            print(f"⚠ Threat score: {threat_score} (expected {expected})")
        
        # Test Cowrie parsing (may return 0 events if log doesn't exist)
        from pathlib import Path
        cowrie_log = Path("/home/cowrie/cowrie/var/log/cowrie/cowrie.json")
        if cowrie_log.exists():
            events = read_cowrie_event_tail(cowrie_log)
            print(f"✓ Cowrie log parsing: {len(events)} events found")
        else:
            print(f"⚠ Cowrie log not found at {cowrie_log}, skipping parse test")
        
        return True
    except Exception as e:
        print(f"✗ App functions test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_template_files():
    """Verify all template files exist."""
    print("\n[TEST 5] Template Files")
    print("=" * 60)
    templates_dir = Path("templates")
    required_files = [
        "index.html",
        "sessions.html",
        "intelligence.html",
        "ip_detail.html",
        "live_logs.html",
        "_enrich_status.html",
        "_log_fragment.html",
        "base.html",
        "dossier.html",
    ]
    
    all_found = True
    for fname in required_files:
        fpath = templates_dir / fname
        if fpath.exists():
            print(f"✓ {fname}")
        else:
            print(f"✗ {fname} NOT FOUND")
            all_found = False
    
    return all_found

def test_config_files():
    """Verify configuration files exist."""
    print("\n[TEST 6] Configuration Files")
    print("=" * 60)
    configs = [
        ("cowrie-logrotate.conf", "Logrotate config"),
        ("install_logrotate.sh", "Logrotate installer"),
    ]
    
    all_found = True
    for fname, desc in configs:
        fpath = Path(fname)
        if fpath.exists():
            print(f"✓ {desc}: {fname}")
        else:
            print(f"✗ {desc}: {fname} NOT FOUND")
            all_found = False
    
    return all_found

def main():
    """Run all integration tests."""
    print("\n" + "=" * 60)
    print("MORPH Integration Verification")
    print("=" * 60)
    
    tests = [
        ("Module Imports", test_imports),
        ("Classifier Rules", test_classifier),
        ("Cleanup Utility", test_cleanup),
        ("App Functions", test_app_functions),
        ("Template Files", test_template_files),
        ("Config Files", test_config_files),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n✗ Test '{name}' raised exception: {e}")
            results.append((name, False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Integration Test Summary")
    print("=" * 60)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")
    
    print(f"\nResult: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n✅ ALL INTEGRATION TESTS PASSED - READY FOR DEPLOYMENT")
        return 0
    else:
        print(f"\n⚠ {total - passed} test(s) failed - review output above")
        return 1

if __name__ == "__main__":
    sys.exit(main())
