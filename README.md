<p align="center">
  <a href="https://ag.tavardt.com/fr/">
    <img src="https://ag.tavardt.com/img/tavardt-banner.png" alt="TAVARDT" width="1024" />
  </a>
</p>

# Auditeur de Sécurité pour Serveurs et Outils MCP

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-5b3cf5.svg)](https://tavardt-france.github.io/mcp-security-auditor-fr/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

***

Auditeur de sécurité de configuration et moteur de durcissement automatisé pour serveurs Model Context Protocol (MCP) et clients IA développé par **TAVARDT**. Analyse les manifestes d'intégration face aux interpréteurs shell directs, montages de volumes dangereux, identifiants en texte clair, paquets non verrouillés et requêtes SSRF vers les métadonnées cloud.

***

## Fonctionnalités Clés et Architecture Défensive

* **Contrôle du Moindre Privilège** : Audite les déclarations de serveurs au sein des fichiers de configuration selon des règles strictes de confiance zéro.
* **Durcissement Automatisé des Déclarations** : Génère des fichiers de configuration sécurisés isolant les commandes dans des conteneurs en lecture seule et extrayant les secrets vers l'environnement hôte.
* **Intégration Continue Modulaire** : S'exécute en ligne de commande locale, en barrière de sécurité CI/CD avec code de sortie strict ou en générateur de rapports JSON structurés.

***

## Vecteurs de Risque et Impact Opérationnel

Des configurations permissives de serveurs MCP exposent le système d'exploitation hôte et les données locales à des mouvements latéraux, au vol d'informations et à des exécutions distantes non autorisées. Le scanner neutralise six vecteurs de menace pour sécuriser les déploiements d'agents autonomes :

* **Invocations Directes d'Interpréteurs Shell (`Exécution de Commandes`)** : Détecte les commandes shell telles que bash, powershell ou cmd s'exécutant sans isolation par conteneur (-35 points de pénalité, CRITIQUE).
* **Arguments d'Évaluation Dynamique de Code (`Exécution de Commandes`)** : Intercepte les paramètres d'évaluation arbitraire comme -c, /c, invoke-expression ou eval (-25 points de pénalité, CRITIQUE).
* **Montages de la Racine et Répertoires Sensibles (`Accès Fichiers`)** : Bloque le montage complet du stockage hôte (-35 points) et l'accès aux clés SSH, identifiants AWS et répertoires système (-30 points de pénalité, CRITIQUE).
* **Identifiants et Clés Secrètes en Texte Clair (`Secrets Exposés`)** : Signale les mots de passe de bases de données et jetons privés stockés sans références aux variables d'environnement (-20 points de pénalité, HAUT).
* **Tentatives SSRF vers les Métadonnées Cloud (`Sécurité Réseau`)** : Intercepte les arguments ciblant les services internes de métadonnées d'instances virtuelles (-20 points de pénalité, HAUT).
* **Exécution de Paquets Distants sans Version Figée (`Sécurité de la Chaîne d'Approvisionnement`)** : Détecte les exécutions npx, uvx ou pipx dépourvues de balise de version immuable (-10 points de pénalité, MOYEN).

La note de sécurité commence à 100 points et subit des déductions pour chaque anomalie confirmée. L'absence d'anomalie atteste de la conformité au principe de moindre privilège, tandis que les failles critiques stoppent net les flux d'intégration.

***

## Installation et Utilisation CLI

Auditez les configurations localement ou configurez des barrières de contrôle dans vos flux de déploiement grâce à Python :

```bash
# Cloner le dépôt officiel
git clone https://github.com/TAVARDT-France/mcp-security-auditor-fr.git

# Accéder au dossier de travail
cd mcp-security-auditor-fr

# Auditer un fichier de configuration MCP
python mcp_security_scanner.py -f mcp.json

# Exécuter en mode de validation strict
python mcp_security_scanner.py -f mcp.json -s

# Générer une configuration durcie et exporter en JSON
python mcp_security_scanner.py -f mcp.json -o hardened_mcp.json -j
```

***

## FAQ Technique

### Quels vecteurs de vulnérabilité sont analysés par l'auditeur dans les configurations MCP ?

L'outil inspecte les manifestes contre l'exécution directe d'interpréteurs shell, les arguments d'exécution dynamique, le montage du système de fichiers racine, l'exposition d'identifiants, les paquets non verrouillés et les requêtes SSRF vers les métadonnées cloud. Chaque anomalie détectée soustrait des pénalités précises sur un score défensif initial de 100 points.

### Comment le scanner prévient-il les risques d'élévation de privilèges liés aux points de montage ?

L'auditeur classe comme critiques les montages du système de fichiers racine ainsi que l'accès aux répertoires sensibles tels que les clés SSH, les accès AWS et les dossiers système. L'assainissement automatique via l'option -o redirige ces accès vers des bacs à sable isolés conformément au principe du moindre privilège.

### Pourquoi les arguments dynamiques comme -c ou les appels d'évaluation sont-ils considérés comme critiques ?

L'activation de paramètres dynamiques permet aux modèles d'IA ou aux entrées hostiles d'exécuter des commandes système arbitraires sur l'environnement hôte. La neutralisation de ces indicateurs garantit que les outils exécutent uniquement des fichiers binaires strictement paramétrés et cloisonnés.

### De quelle manière la fonction de renforcement automatique protège-t-elle les clés et secrets exposés ?

Le mécanisme de durcissement activé avec l'option -o convertit les chaînes de connexion et jetons d'authentification en clair en variables d'environnement configurées sur l'hôte. Cette abstraction évite toute fuite accidentelle d'identifiants sensibles dans les journaux d'agents ou les dépôts de versions partagés.

### L'utilitaire peut-il s'intégrer dans les chaînes d'intégration continue et pipelines CI/CD ?

L'outil CLI analyse directement les fichiers de configuration via l'argument -f et propose un mode strict -s qui déclenche un code de sortie 1 en présence de vulnérabilités. Associé à la sortie structurée -j, il permet d'automatiser le blocage immédiat des livraisons logicielles non conformes.

***

## Liens Utiles

* **Portail Institutionnel:** https://ag.tavardt.com/fr/
* **Suite de Diagnostic:** https://tools.tavardt.com/fr/
* **Contact Technique:** https://ag.tavardt.com/fr/contact/

***

### Licence
Distribué sous licence MIT. Consultez [LICENSE](LICENSE) pour plus d'informations.

***

© 2026 TAVARDT. Tous droits réservés.
