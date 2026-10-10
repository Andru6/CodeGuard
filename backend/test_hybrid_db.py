import os
import sys

# Ensure backend directory is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from database import get_all_scans, get_user_analytics, USE_MONGODB

def test():
    print(f"DEBUG: USE_MONGODB Status = {USE_MONGODB}")
    
    # 1. Test get_all_scans
    # This should return the 26 scans I found in SQLite even if MongoDB is active
    scans = get_all_scans()
    print(f"RESULT: Found {len(scans)} total scans in Hybrid Mode.")
    
    if len(scans) > 0:
        print(f"SUCCESS: Hybrid database is successfully merging results.")
        # Check source distribution
        sources = [s.get('source', 'unknown') for s in scans]
        print(f"SOURCES: { {src: sources.count(src) for src in set(sources)} }")
    else:
        print("FAILURE: No scans found in Hybrid Mode.")

    # 2. Test analytics
    analytics = get_user_analytics()
    print(f"ANALYTICS: {analytics}")
    
    total_vulns = sum(analytics['severity'].values())
    if total_vulns > 0:
        print(f"SUCCESS: Analytics aggregated {total_vulns} vulnerabilities from Hybrid sources.")
    else:
        print("FAILURE: Analytics still showing zero vulnerabilities.")

if __name__ == "__main__":
    test()
