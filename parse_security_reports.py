import json
import os

# Chemin vers le rapport global téléchargé
path = "reports/global/global-report.json"

if not os.path.exists(path):
    print(f"❌ Le fichier {path} n'existe pas.")
    exit(1)

print("✅ Chargement du rapport global...")
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

# Extraction des infos utiles
summary = {
    "npm_audit_vuln_count": len(data.get("sast", {}).get("npm_audit", {}).get("vulnerabilities", {})),
    "eslint_error_count": len(data.get("sast", {}).get("eslint", [])),
    "sca_vuln_count": len(data.get("sca", {}).get("vulnerabilities", {})),
    "zap_scan_size": len(data.get("dast", {})),
}

# Identifier les vulnérabilités critiques
vulns = data.get("sast", {}).get("npm_audit", {}).get("vulnerabilities", {})
critical_vulns = [k for k, v in vulns.items() if v.get("severity") == "critical"]
summary["critical_vulnerabilities"] = critical_vulns

# Sauvegarde du résumé
os.makedirs("reports/global", exist_ok=True)
summary_path = "reports/global/summary.json"

with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)

print("✅ Résumé généré avec succès :", summary_path)
