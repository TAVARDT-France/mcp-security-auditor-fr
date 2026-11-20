# Auditeur de Sécurité pour Serveurs et Outils MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![Standard](https://img.shields.io/badge/Standard-ANSSI%20Moindre%20Privilege-3b82f6?style=for-the-badge)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981?style=for-the-badge)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditeur de sécurité pour serveurs et outils MCP (Model Context Protocol). Application web client et outil CLI.

Conçu pour les organisations et équipes techniques en **France**, ce dépôt fournit un outil autonome pour auditer et sécuriser les configurations du **Model Context Protocol (MCP)**, prévenant les escalades de privilèges au sein des agents d'Intelligence Artificielle.

---

## Modes d'Utilisation

### 1. Application Web Client (GitHub Pages)
Accessible directement depuis un navigateur web :
- **Lien Officiel** : [https://tavardt-france.github.io/mcp-security-auditor-fr/](https://tavardt-france.github.io/mcp-security-auditor-fr/)
- **Confidentialité Native** : Exécution 100% côté client dans le moteur JavaScript de votre navigateur. Aucune donnée n'est transmise vers des serveurs tiers.

### 2. Outil en Ligne de Commande (CLI)
Pour les flux d'intégration continue (CI/CD) ou les audits locaux :

```bash
# Analyse d'un fichier de configuration
python mcp_security_scanner.py --file mcp.json

# Mode strict pour pipeline CI/CD (échec avec code 1 en cas d'anomalie)
python mcp_security_scanner.py --file mcp.json --strict

# Génération automatique d'une configuration sécurisée (Hardened)
python mcp_security_scanner.py --file mcp.json --harden mcp-hardened.json

# Export des résultats au format JSON
python mcp_security_scanner.py --file mcp.json --json
```

---

## Vecteurs de Sécurité Audités

1. **Périmètre du Système de Fichiers** : Contrôle des montages à la racine (`/`, `C:\`) ou dans les dossiers sensibles (`/etc`, `~/.ssh`).
2. **Exécution de Commandes et Interpréteurs Shell** : Blocage de l'invocation directe de terminaux non isolés (`bash`, `sh`, `powershell`, `cmd`).
3. **Protection des Secrets et Clés d'API** : Détection de mots de passe, jetons d'accès et identifiants en clair.
4. **Sécurité de la Chaîne d'Approvisionnement** : Vérification du verrouillage strict des versions de paquets (`npx`, `uvx`).
5. **Prévention du SSRF** : Filtrage des requêtes vers les interfaces locales et les adresses internes non autorisées.

---

## Exemple d'Intégration GitHub Actions

```yaml
name: MCP Security Gate
on: [push, pull_request]

jobs:
  audit-mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configurer Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Exécuter Audit MCP
        run: |
          python mcp_security_scanner.py --file config/mcp.json --strict
```

---

## Cadre de Conformité

- **Juridiction** : France
- **Référentiel Technique** : Directives de Moindre Privilège et Référentiels ANSSI pour l'IA
- **Organisation Responsable** : [TAVARDT-France](https://github.com/TAVARDT-France)

## Portails TAVARDT

- **Portail Principal** : [https://ag.tavardt.com/fr/](https://ag.tavardt.com/fr/)
- **Portail d'Outils**: [https://tools.tavardt.com/fr/](https://tools.tavardt.com/fr/)
- **Contact Technique** : [https://ag.tavardt.com/fr/contact/](https://ag.tavardt.com/fr/contact/)

---

### Licence
Distribué sous licence MIT. Consultez le fichier [LICENSE](LICENSE) pour plus d'informations.
