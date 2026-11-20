#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT France
Auditeur de Securite pour Serveurs et Outils MCP
Auditeur de securite pour serveurs et outils MCP (Model Context Protocol). Application web client et outil CLI.

Standard: Directives de Moindre Privilege et Referentiels ANSSI pour l IA
Repository: https://github.com/TAVARDT-France/mcp-security-auditor-fr
Online Web App: https://tavardt-france.github.io/mcp-security-auditor-fr/
"""

import os
import sys
import json
import re
import argparse

DANGEROUS_SHELLS = ["bash", "sh", "zsh", "powershell", "powershell.exe", "cmd", "cmd.exe"]
ROOT_PATHS = ["/", "\\", "c:\\", "c:/", "d:\\", "d:/", "~", "$home", "%userprofile%"]
SENSITIVE_PATHS = ["/etc", "/var", "/root", ".ssh", ".aws", ".gnupg", "system32", "appdata"]
METADATA_IPS = ["169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1"]

def analyze_mcp_config(config_data):
    servers = {}
    if "mcpServers" in config_data and isinstance(config_data["mcpServers"], dict):
        servers = config_data["mcpServers"]
    elif isinstance(config_data, dict):
        servers = config_data

    findings = []
    penalty = 0

    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue

        cmd = (srv.get("command") or "").strip().lower()
        args = srv.get("args") or []
        env = srv.get("env") or {}

        # 1. Shell execution
        if cmd in DANGEROUS_SHELLS:
            findings.append({
                "server": s_name,
                "severity": "CRITICAL",
                "category": "Execution de Commandes",
                "title": "Execution Directe d un Interpreteur Shell Detectee",
                "detail": "Le serveur execute directement '{cmd}' sans isolation de processus.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Supprimez l execution directe de shells. Privilegiez des conteneurs Docker isoles."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Execution de Commandes",
                    "title": "Arguments Contenant des Parametres d Execution Arbitraire",
                    "detail": "Le parametre '{arg}' a ete detecte, autorisant des instructions dynamiques.".replace("{arg}", str(arg)),
                    "remediation": "Supprimez les flags comme -c ou eval. Parametrez les outils de maniere stricte."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acces aux Fichiers",
                    "title": "Montage de la Racine du Systeme de Fichiers",
                    "detail": "Le chemin '{path}' attribue des droits totaux a l integralite du disque de l hote.".replace("{path}", str(arg)),
                    "remediation": "Restreignez les chemins autorises a des dossiers specifiques."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Acces aux Fichiers",
                    "title": "Acces Autorise a des Repertoires Systeme Sensibles",
                    "detail": "Le serveur a acces a des fichiers situes dans '{path}'.".replace("{path}", str(arg)),
                    "remediation": "Interdisez l acces aux cles SSH et repertoires proteges du systeme d exploitation."
                })
                penalty += 30

        # 4. Exposed secrets in env
        for e_key, e_val in env.items():
            val = str(e_val or "").strip()
            if val.startswith("${") and val.endswith("}"):
                continue

            is_secret_key = bool(re.search(r"token|secret|key|password|passwd|auth|bearer", e_key, re.I))
            is_sensitive_url = bool(re.search(r"postgres:|mongodb:|mysql:|redis:", val, re.I) and "@" in val)
            is_known_prefix = bool(re.match(r"^sk-[a-zA-Z0-9_-]{20,}|^ghp_[a-zA-Z0-9]{20,}|^xoxb-[a-zA-Z0-9-]{20,}|^AKIA[0-9A-Z]{16}", val))

            if is_sensitive_url:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Secrets et Identifiants",
                    "title": "Chaine de Connexion a la Base avec Mot de Passe en Clair",
                    "detail": "La variable d environnement '{key}' expose des identifiants d acces dans le manifeste.".replace("{key}", e_key),
                    "remediation": "Remplacez par une reference a variable d environnement : ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 30
            elif is_known_prefix or (is_secret_key and len(val) >= 10):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Secrets et Identifiants",
                    "title": "Cle d API ou Jeton Prive Expose en Texte Clair",
                    "detail": "La variable '{key}' contient un jeton secret encode directement dans le fichier.".replace("{key}", e_key),
                    "remediation": "Utilisez les variables d environnement du systeme hote : ${{ {key} }}.".replace("{key}", e_key)
                })
                penalty += 25

        # 5. Supply chain / unpinned packages
        if cmd in ["npx", "uvx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for arg in args:
                a_str = str(arg)
                if a_str == "-y" or a_str.startswith("--"):
                    continue
                if not pkg_found and ("/" in a_str or "-" in a_str or len(a_str) > 2):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str and a_str.rfind("@") > 0:
                        is_pinned = True
                    if "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Chaine Logistique Logicielle",
                    "title": "Paquet Distant sans Verrouillage de Version (Risque Supply Chain)",
                    "detail": "Le paquet '{pkg}' est telecharge dynamiquement sans mention de version immuable.".replace("{pkg}", pkg_name),
                    "remediation": "Verrouillez la version exacte (ex : {pkg}@1.0.0 ou ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_IPS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Reseau et SSRF",
                    "title": "Risque de SSRF ou Requete vers les Metadonnees Cloud",
                    "detail": "L argument '{target}' cible des services locaux ou l IP des metadonnees cloud.".replace("{target}", a_str),
                    "remediation": "Configurez des listes blanches de domaines et bloquez les IP de metadonnees."
                })
                penalty += 20

    score = max(0, 100 - penalty)
    return {
        "server_count": len(servers),
        "score": score,
        "findings": findings,
        "servers": servers
    }

def harden_config(servers):
    hardened = {"mcpServers": {}}
    for s_name, srv in servers.items():
        if not isinstance(srv, dict):
            continue
        h_cmd = srv.get("command", "")
        h_args = list(srv.get("args") or [])

        # Wrap shells
        if h_cmd.lower() in DANGEROUS_SHELLS:
            h_cmd = "docker"
            h_args = ["run", "--rm", "-i", "--read-only", "--cap-drop=ALL", "sandbox-runner:latest"]

        # Restrict root or critical paths
        cleaned_args = []
        for a in h_args:
            a_str = str(a).strip().lower()
            if a_str in ROOT_PATHS:
                cleaned_args.append("/workspace/sandbox/app-data")
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                cleaned_args.append("/workspace/sandbox/isolated-storage")
            elif "169.254.169.254" in a_str:
                cleaned_args.append("127.0.0.1:blocked")
            elif h_cmd in ["npx", "uvx"] and a_str.startswith("@modelcontextprotocol/server-") and "@" not in a_str[1:]:
                cleaned_args.append(str(a) + "@0.6.2")
            else:
                cleaned_args.append(a)

        h_srv = {
            "command": h_cmd,
            "args": cleaned_args
        }

        # Abstract secrets into env vars
        if "env" in srv and isinstance(srv["env"], dict):
            h_env = {}
            for e_k, e_v in srv["env"].items():
                v_str = str(e_v or "")
                if v_str.startswith("${") and v_str.endswith("}"):
                    h_env[e_k] = v_str
                else:
                    h_env[e_k] = "${" + e_k.upper() + "}"
            h_srv["env"] = h_env

        hardened["mcpServers"][s_name] = h_srv
    return hardened

def main():
    parser = argparse.ArgumentParser(
        description="Auditeur de Securite pour Fichiers de Configuration MCP (Model Context Protocol)."
    )
    parser.add_argument("--file", "-f", required=True, help="Chemin vers le fichier mcp.json ou claude_desktop_config.json")
    parser.add_argument("--strict", action="store_true", help="Mode strict : quitter avec code 1 en cas de moindre anomalie")
    parser.add_argument("--harden", "-o", help="Exporter le fichier JSON avec configuration securisee et corrigee")
    parser.add_argument("--json", action="store_true", help="Afficher le resultat au format JSON structure")

    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    try:
        with open(args.file, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:
        print(f"Error reading JSON from {args.file}: {e}", file=sys.stderr)
        sys.exit(2)

    report = analyze_mcp_config(cfg)

    if args.harden:
        hardened_json = harden_config(report["servers"])
        with open(args.harden, "w", encoding="utf-8") as out_f:
            json.dump(hardened_json, out_f, indent=2)
        print(f"Configuration securisee enregistree avec succes dans: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"AUDIT DE SECURITE MCP: TAVARDT France")
        print(f"Standard: Directives de Moindre Privilege et Referentiels ANSSI pour l IA")
        print(f"Serveurs Analyses: {report['server_count']}")
        print(f"Score de Securite: {report['score']} / 100")
        print(f"Vulnerabilites Detectees: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Aucune vulnerabilite detectee. Configuration conforme au principe de moindre privilege.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    # Exit code determination
    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
