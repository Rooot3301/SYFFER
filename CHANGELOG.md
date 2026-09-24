# Changelog

## 0.3.0 - 2026-09-24

### Ajouts (Phase 1 — port scan + fingerprinting)
- Nouvelle option de menu "Scan avancé (nmap)" avec 5 profils
  prédéfinis (Quick, Full TCP, Service+Version, OS Detection,
  Aggressive) + mode Custom (checkbox de flags + ports validés).
- Wrapper `NmapTool` (sous-classe d'`ExternalTool`) : construction
  100% liste de la ligne de commande, whitelist de flags,
  assertion défensive sur la cible.
- Parser XML nmap (`syffer.core.nmap_parser.parse_xml`) via
  `xml.etree.ElementTree` (stdlib, aucune nouvelle dépendance).
- Banner grabbing TCP passif (`syffer.core.banner_grab.grab_banner`)
  en complément de nmap, activable par confirm.
- Orchestrateur `syffer.core.port_scan.port_scan` : validation
  target/ports, sauvegarde du XML brut sous `extract/nmap-*.xml`,
  enrichissement banner sur les ports "open" uniquement.
- Extensions `validate_hostname`, `validate_target`, `validate_ports`.
- Export `NmapScan` en txt / json / csv (csv aplati, une ligne par
  port).
- Fixture XML nmap embarquée dans `tests/fixtures/` (aucun nmap réel
  invoqué en CI).

### Prérequis ajoutés
- nmap ≥ 7.90 sur le PATH pour l'option "Scan avancé (nmap)".
  L'outil refuse proprement (message + retour menu) si absent, sans
  jamais crasher.

### Sécurité
- Aucun flag nmap n'est saisissable en champ libre : le mode Custom
  passe par des checkbox pour `-sV -sC -O -Pn` uniquement, et par
  `validate_ports` pour la spec de ports.
- La cible est validée en amont (`validate_target`), et une
  assertion défensive dans `NmapTool.run_scan` refuse toute cible
  contenant un caractère hors `[A-Za-z0-9.:/-]`.

## 0.2.0 - 2026-09-24

### Breaking changes
- Le script `Syffer.py` racine est supprimé, remplacé par le package
  `syffer/` et l'entry point console `syffer`.
- L'installation se fait désormais via `pip install -e .` (ou `pipx
  install .`). L'ancien `pip install -r requirements.txt` reste
  compatible pour les dépendances runtime.
- La dépendance `netifaces` est retirée (cassée sur Python 3.12), remplacée
  par `psutil`.
- La dépendance `colorama` est retirée, remplacée par `rich`.

### Ajouts
- Menu interactif propre avec navigation fléchée (`questionary` +
  `rich`) qui boucle jusqu'à "Quitter".
- Filtres BPF pour la capture de paquets.
- Export unifié en txt / json / csv pour tous les types de résultats.
- Logging structuré avec mode verbeux activable via l'option
  "Paramètres" du menu.
- Wrapper `ExternalTool` préparé pour brancher nmap en Phase 1.
- Suite de tests `pytest` couvrant validation, exporter, formatters,
  handlers du menu (mocks scapy/psutil/requests, aucun droit admin
  requis).

### Corrections
- L'option "Scan du réseau" ne plante plus (ancien
  `TypeError` sur `generate_report`).
- L'option "Détails d'un paquet" est enfin fonctionnelle : les
  paquets capturés persistent tant que le menu tourne.
- Les noms de rapport sont sanitisés (`safe_filename`) et le chemin
  d'écriture est vérifié pour rester sous `extract/` (contre path
  traversal).
- Les CIDR et les IP sont validés avant les appels réseau.
- Les filtres BPF sont validés (rejette les caractères shell
  dangereux) avant d'être passés à scapy.

### Retrait
- Fichier racine `Syffer.py`.
- Dépendances `netifaces`, `colorama`.
