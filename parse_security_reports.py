import json
import os

# === 1. Vérification de l'existence du rapport global ===
global_report_path = "reports/global/global-report.json"

if not os.path.exists(global_report_path):
    print("❌ Le fichier global-report.json n'existe pas.")
    exit(1)

print("✅ Chargement du rapport global...")
with open(global_report_path, "r", encoding="utf-8") as f:
    data = json.load(f)

# === 2. Extraire des informations utiles ===
summary = {}

# SAST npm audit
npm_audit = data.get("sast", {}).get("npm_audit", {})
summary["npm_audit_vuln_count"] = len(npm_audit.get("vulnerabilities", {})) if "vulnerabilities" in npm_audit else 0

# SAST ESLint
eslint_report = data.get("sast", {}).get("eslint", [])
summary["eslint_error_count"] = len(eslint_report) if isinstance(eslint_report, list) else 0

# SCA
sca_report = data.get("sca", {})
summary["sca_vuln_count"] = len(sca_report.get("vulnerabilities", {})) if "vulnerabilities" in sca_report else 0

# DAST
dast_report = data.get("dast", {})
summary["dast_status"] = dast_report.get("status", "unknown")
summary["dast_message"] = dast_report.get("message", "")

# === 3. Identifier les vulnérabilités critiques dans npm audit ===
critical_vulns = []
if "vulnerabilities" in npm_audit:
    for name, details in npm_audit["vulnerabilities"].items():
        if details.get("severity") == "critical":
            critical_vulns.append(name)
summary["critical_vulnerabilities"] = critical_vulns

# === 4. Sauvegarder le résumé ===
os.makedirs("reports/global", exist_ok=True)
summary_path = "reports/global/summary.json"

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print("✅ Résumé généré avec succès :", summary_path)
print(json.dumps(summary, indent=2, ensure_ascii=False))
