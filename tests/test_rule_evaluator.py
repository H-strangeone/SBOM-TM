from src.sbom_tm.rule_engine import RuleEngine
import json, os

def run_demo():
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    rules_dir = os.path.join(base, "rules")
    engine = RuleEngine.from_directory(rules_dir)
    
    items = [
        {
            "component": {"name": "example", "version": "1.0.0", "purl": "pkg:type/example@1.0.0"},
            "vulnerability": {"id": "CVE-2021-1234", "severity": "HIGH", "cvss": 8.5},
        },
        {
            "component": {"name": "libX", "version": "0.1.0", "license": "GPL-3.0"},
        },
    ]
    
    results = []
    for item in items:
        component = item.get("component", {})
        vuln = item.get("vulnerability", {})
        evaluated = engine.evaluate(component, vuln, context={}, threatintel={})
        results.extend(evaluated)
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run_demo()
