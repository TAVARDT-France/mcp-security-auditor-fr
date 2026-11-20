#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TAVARDT France
Auditeur de Sécurité pour Serveurs et Outils MCP
Auditeur de sécurité pour serveurs et outils MCP (Model Context Protocol). Application web client et outil CLI.

Standard: Directives de Moindre Privilège et Référentiels ANSSI pour l'IA
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
METADATA_HOSTS = ["metadata.cloud-provider.internal", "metadata.internal", "instance-data.internal", "cloud-metadata.service"]

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
                "category": "Exécution de Commandes",
                "title": "Exécution Directe d'Interpréteur de Shell Détectée",
                "detail": "Le serveur exécute l'interpréteur '{cmd}' directement sans isolation dans un conteneur.".replace("{cmd}", srv.get("command", "")),
                "remediation": "Supprimez l'exécution directe de shells. Utilisez des conteneurs Docker isolés avec privilèges minimaux."
            })
            penalty += 35

        # 2. Dynamic command flags
        for arg in args:
            a_str = str(arg).lower()
            if a_str in ["-c", "/c", "-command"] or "invoke-expression" in a_str or "eval(" in a_str:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Exécution de Commandes",
                    "title": "Paramètres d'Exécution Arbitraire de Commandes",
                    "detail": "Le paramètre '{arg}' autorise l'exécution dynamique d'instructions.".replace("{arg}", str(arg)),
                    "remediation": "Supprimez les paramètres comme -c ou les évaluations dynamiques. Paramétrez les outils de manière stricte."
                })
                penalty += 25

        # 3. Filesystem mounting
        for arg in args:
            a_str = str(arg).strip().lower()
            if a_str in ROOT_PATHS:
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Accès au Système de Fichiers",
                    "title": "Montage de la Racine du Système de Fichiers",
                    "detail": "Le chemin '{path}' accorde un accès complet à l'ensemble du disque hôte.".replace("{path}", str(arg)),
                    "remediation": "Limitez les chemins autorisés à des répertoires de travail dédiés et isolés."
                })
                penalty += 35
            elif any(sp in a_str for sp in SENSITIVE_PATHS):
                findings.append({
                    "server": s_name,
                    "severity": "CRITICAL",
                    "category": "Accès au Système de Fichiers",
                    "title": "Accès Autorisé à des Dossiers Sensibles du Système",
                    "detail": "Le serveur a la permission de lire des fichiers dans des répertoires protégés ('{path}').".replace("{path}", str(arg)),
                    "remediation": "Bloquez l'accès aux clés SSH et aux répertoires confidentiels du système d'exploitation."
                })
                penalty += 30

        # 4. Plaintext secrets
        for env_k, env_v in env.items():
            k_lower = env_k.lower()
            v_str = str(env_v or "")
            if any(s_k in k_lower for s_k in ["db_url", "database_url", "conn_str", "postgres", "mysql"]):
                if "password" in v_str.lower() or "://" in v_str:
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Identifiants Exposés",
                        "title": "Chaîne de Connexion de Base de Données en Texte Clair",
                        "detail": "La variable d'environnement '{key}' contient des identifiants de connexion exposés.".replace("{key}", env_k),
                        "remediation": "Remplacez par une variable d'environnement : ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20
            elif any(s_k in k_lower for s_k in ["api_key", "secret", "token", "auth", "private_key"]):
                if not (v_str.startswith("${") and v_str.endswith("}")):
                    findings.append({
                        "server": s_name,
                        "severity": "HIGH",
                        "category": "Identifiants Exposés",
                        "title": "Clé d'API ou Jeton Privé Exposé en Texte Clair",
                        "detail": "La variable '{key}' contient un jeton secret encodé directement.".replace("{key}", env_k),
                        "remediation": "Utilisez des variables d'environnement du système hôte : ${{ {key} }}.".replace("{key}", env_k)
                    })
                    penalty += 20

        # 5. Supply chain unpinned packages
        if cmd in ["npx", "uvx", "pipx"]:
            pkg_found = False
            is_pinned = False
            pkg_name = ""
            for a in args:
                a_str = str(a)
                if not a_str.startswith("-"):
                    pkg_found = True
                    pkg_name = a_str
                    if "@" in a_str[1:] or "==" in a_str:
                        is_pinned = True
            if pkg_found and not is_pinned:
                findings.append({
                    "server": s_name,
                    "severity": "MEDIUM",
                    "category": "Chaîne d'Approvisionnement",
                    "title": "Paquet Distant sans Version Figée (Risque de Supply Chain)",
                    "detail": "Le paquet '{pkg}' est téléchargé dynamiquement sans spécification de version immuable.".replace("{pkg}", pkg_name),
                    "remediation": "Figez la version exacte du paquet (exemple : {pkg}@1.0.0 ou ==1.0.0).".replace("{pkg}", pkg_name)
                })
                penalty += 10

        # 6. SSRF / Metadata
        for arg in args:
            a_str = str(arg)
            if any(mip in a_str for mip in METADATA_HOSTS):
                findings.append({
                    "server": s_name,
                    "severity": "HIGH",
                    "category": "Réseau et Prévention SSRF",
                    "title": "Risque de SSRF ou Accès aux Métadonnées Cloud",
                    "detail": "Le paramètre '{target}' cible des services de métadonnées internes ou des points d'accès protégés.".replace("{target}", a_str),
                    "remediation": "Configurez des listes d'autorisation strictes de domaines d'entreprise et bloquez les services de métadonnées internes."
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
            elif any(mh in a_str for mh in METADATA_HOSTS):
                cleaned_args.append("metadata-blocked.internal")
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
        description="Auditeur de Sécurité pour Fichiers de Configuration MCP (Model Context Protocol)."
    )
    parser.add_argument("--file", "-f", required=True, help="Chemin vers le fichier mcp.json ou configuration du client d'intelligence artificielle")
    parser.add_argument("--strict", action="store_true", help="Mode strict : terminer avec le code 1 si une anomalie est détectée")
    parser.add_argument("--harden", "-o", help="Exporter le fichier JSON avec une configuration corrigée et sécurisée")
    parser.add_argument("--json", action="store_true", help="Afficher la sortie au format JSON structuré")

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
        print(f"Configuration sécurisée enregistrée avec succès sous: {args.harden}")

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print("=" * 64)
        print(f"AUDIT DE SÉCURITÉ MCP: TAVARDT France")
        print(f"Standard: Directives de Moindre Privilège et Référentiels ANSSI pour l'IA")
        print(f"Serveurs Analysés: {report['server_count']}")
        print(f"Indice de Sécurité: {report['score']} / 100")
        print(f"Vulnérabilités Détectées: {len(report['findings'])}")
        print("=" * 64)

        if not report["findings"]:
            print("Aucune vulnérabilité détectée. Configuration conforme au principe du moindre privilège.")
        else:
            for idx, finding in enumerate(report["findings"], 1):
                print(f"[{idx}] [{finding['severity']}] {finding['server']}: {finding['title']}")
                print(f"    Category: {finding['category']}")
                print(f"    Detail: {finding['detail']}")
                print(f"    Remediation: {finding['remediation']}")
                print("-" * 64)

    critical_count = sum(1 for f in report["findings"] if f["severity"] == "CRITICAL")
    if critical_count > 0:
        sys.exit(1)
    if args.strict and report["findings"]:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
