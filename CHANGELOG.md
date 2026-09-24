# Changelog

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
