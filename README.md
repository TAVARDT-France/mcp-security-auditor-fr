# Auditeur de Securite pour Serveurs et Outils MCP

[![Live Demo](https://img.shields.io/badge/GitHub%20Pages-Live%20Demo-06b6d4?style=for-the-badge)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![Standard](https://img.shields.io/badge/Standard-ANSSI%20Moindre%20Privilege-3b82f6?style=for-the-badge)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-10b981?style=for-the-badge)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![License](https://img.shields.io/badge/License-MIT-slate?style=for-the-badge)](LICENSE)

Auditeur de securite pour serveurs et outils MCP (Model Context Protocol). Application web client et outil CLI.

Concu pour les organisations et equipes techniques en **France**, ce depot fournit un outil autonome pour auditer et securiser les configurations du **Model Context Protocol (MCP)**, prevenant les escalades de privileges au sein des agents d Intelligence Artificielle.

---

## Modes d Utilisation

### 1. Application Web Client (GitHub Pages)
Accessible directement depuis un navigateur web :
- **Lien Officiel** : [https://tavardt-france.github.io/mcp-security-auditor-fr/](https://tavardt-france.github.io/mcp-security-auditor-fr/)
- **Confidentialite Native** : Execution 100% cote client dans le moteur JavaScript de votre navigateur. Aucune donnee n est transmise vers des serveurs tiers.

### 2. Outil en Ligne de Commande (CLI)
Pour les flux d integration continue (CI/CD) ou les audits locaux :

```bash
# Analyse d un fichier de configuration
python mcp_security_scanner.py --file mcp.json

# Mode strict pour pipeline CI/CD (echec avec code 1 en cas d anomalie)
python mcp_security_scanner.py --file mcp.json --strict

# Generation automatique d une configuration securisee (Hardened)
python mcp_security_scanner.py --file mcp.json --harden mcp-hardened.json

# Export des resultats au format JSON
python mcp_security_scanner.py --file mcp.json --json
```

---

## Vecteurs de Securite Audites

1. **Perimetre du Systeme de Fichiers** : Controle des montages a la racine (`/`, `C:\`) ou dans les dossiers sensibles (`/etc`, `~/.ssh`).
2. **Execution de Commandes et Interpreteurs Shell** : Blocage de l invocation directe de terminaux non isoles (`bash`, `sh`, `powershell`, `cmd`).
3. **Protection des Secrets et Cles d API** : Detection de mots de passe, jetons d acces et identifiants en clair.
4. **Securite de la Chaine d Approvisionnement** : Verification du verrouillage strict des versions de paquets (`npx`, `uvx`).
5. **Prevention du SSRF et Protection des Metadonnees** : Filtrage des requetes vers les interfaces locales et les adresses de metadonnees cloud (`169.254.169.254`).

---

## Exemple d Integration GitHub Actions

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
      - name: Executer Audit MCP
        run: |
          python mcp_security_scanner.py --file config/mcp.json --strict
```

---

## Cadre de Conformite

- **Juridiction** : France
- **Referentiel Technique** : Directives de Moindre Privilege et Referentiels ANSSI pour l IA
- **Organisation Responsable** : [TAVARDT-France](https://github.com/TAVARDT-France)

## Portails TAVARDT

- **Portail Principal** : [https://ag.tavardt.com/fr/](https://ag.tavardt.com/fr/)
- **Outils de Cybersecurite** : [https://tools.tavardt.com/fr/](https://tools.tavardt.com/fr/)
- **Contact Technique** : [https://ag.tavardt.com/fr/contact/](https://ag.tavardt.com/fr/contact/)

---

### Licence
Distribue sous licence MIT. Consultez le fichier [LICENSE](LICENSE) pour plus d informations.
