import json

def generate_report(scan_results):
    return json.dumps(scan_results, indent=4)
