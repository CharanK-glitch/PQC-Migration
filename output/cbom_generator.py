"""CycloneDX 1.7 CBOM (Cryptographic Bill of Materials) generator."""

import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict


def generate_cbom(findings: List[Dict], project_name: str = "Unknown",
                  project_path: str = ".", scan_mode: str = "local") -> Dict:
    """Generate a CycloneDX 1.7 CBOM from scan findings.

    Args:
        findings: List of scan findings
        project_name: Name of the project being scanned
        project_path: Root path of the scanned project
        scan_mode: Scan mode (local, github, live)

    Returns:
        CycloneDX 1.7 CBOM dictionary
    """
    bom_components = {}

    for finding in findings:
        alg = finding.get("algorithm", {})
        rule_id = finding["rule_id"]
        rule_name = finding["rule_name"]
        rel_file = _relative_path(finding["file"], project_path)

        comp_ref = f"pkg:{project_name.lower().replace(' ', '-')}/{rule_id}@{rel_file}"

        occurrence = {
            "file": rel_file,
            "line": finding["line_number"],
            "snippet": finding["content"],
            "language": finding.get("language", "unknown"),
            "source": finding.get("source", "generic"),
        }

        if comp_ref not in bom_components:
            bom_components[comp_ref] = {
                "bom-ref": comp_ref,
                "type": "cryptographic-asset",
                "name": rule_name,
                "version": "1.0",
                "description": f"Cryptographic mechanism found in {rel_file} ({finding.get('language', 'unknown')})",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": alg.get("primitive", "unknown"),
                        "algorithmFamily": alg.get("algorithmFamily", "unknown"),
                        "algorithmName": alg.get("algorithmName", "unknown"),
                        "risk": alg.get("risk", 0),
                        "nistQuantumSecurityLevel": alg.get("nistQuantumSecurityLevel", 0),
                        "classicalSecurityLevel": alg.get("classicalSecurityLevel", 0),
                        "securityProperties": alg.get("securityProperties", []),
                    }
                },
                "properties": [
                    {
                        "name": "occurrences",
                        "value": json.dumps([occurrence])
                    },
                    {
                        "name": "replacement",
                        "value": finding.get("replacement", "See NIST SP 800-208")
                    },
                    {
                        "name": "migration-priority",
                        "value": finding.get("priority", "P2-Medium")
                    },
                    {
                        "name": "migration-effort",
                        "value": finding.get("effort", "Medium")
                    },
                    {
                        "name": "scan-source",
                        "value": finding.get("source", "generic")
                    },
                ]
            }
        else:
            # Append occurrence to existing component
            occ_prop = next(
                (p for p in bom_components[comp_ref]["properties"] if p["name"] == "occurrences"),
                None
            )
            if occ_prop:
                occs = json.loads(occ_prop["value"])
                occs.append(occurrence)
                occ_prop["value"] = json.dumps(occs)

    # Build CBOM
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pgcrypto-scanner",
                        "version": "1.0.0"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": project_name,
                "version": "scanned"
            }
        },
        "components": list(bom_components.values()),
        "dependencies": []
    }

    # Add dependency relationships
    for ref in bom_components:
        cbom["dependencies"].append({"ref": ref, "dependsOn": []})

    return cbom


def _relative_path(filepath: str, base_path: str) -> str:
    """Get relative path from base."""
    if filepath.startswith(base_path):
        return filepath[len(base_path):].lstrip("/")
    return filepath


def save_cbom(cbom: Dict, output_path: str):
    """Save CBOM to JSON file.

    Args:
        cbom: CBOM dictionary
        output_path: Path to save the file
    """
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(cbom, f, indent=2)
