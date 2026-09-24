# Syffer

> Outil CLI de recon réseau : capture de paquets, scan ARP, port scan avancé (nmap), fingerprinting, géolocalisation IP.
> **Recon uniquement.** Pas d'exploitation active, pas de brute-force, pas de Metasploit.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://img.shields.io/badge/tests-151%20passing-brightgreen)
![Version](https://img.shields.io/badge/version-0.3.0-orange)

---

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Démarrage rapide](#démarrage-rapide)
- [Options du menu](#options-du-menu)
- [Zoom : Scan avancé nmap](#zoom--scan-avancé-nmap)
- [Exports](#exports)
- [Structure du projet](#structure-du-projet)
- [Développement](#développement)
- [Roadmap](#roadmap)
- [Usage éthique](#usage-éthique)
- [Licence](#licence)

---

## Fonctionnalités

- **Capture de paquets** avec filtres BPF, sauvegarde `.pcap` horodatée
- **Scan ARP** du réseau local, résolution vendor MAC locale (sans appel réseau)
- **Scan avancé nmap** — 5 profils prédéfinis + mode Custom, banner grabbing passif en complément
- **Fingerprinting** — services + versions (`-sV`), OS (`-O`), scripts NSE (`-sC`)
- **Infos réseau** — hostname, IP locale, interfaces cross-platform (psutil)
- **Géolocalisation IP** publique via ip-api.com
- **Export unifié** en `txt` / `json` / `csv` pour tous les résultats
- **Menu interactif** à navigation fléchée, rendu Rich (tableaux, panels, couleurs)
- **Logging structuré** avec mode verbeux à la volée

---

## Prérequis

| Composant | Version | Obligatoire | Rôle |
|---|---|---|---|
| Python | ≥ 3.10 | ✅ | Runtime |
| Npcap _(Windows)_ | dernière | ⚠️ pour capture / ARP | Accès raw sockets |
| Root/CAP_NET_RAW _(Linux/macOS)_ | — | ⚠️ pour capture / ARP / nmap `-O` | Accès raw sockets |
| [nmap](https://nmap.org/download.html) | ≥ 7.90 | ⚠️ pour "Scan avancé (nmap)" | Port scan + fingerprinting |

Sans nmap, l'option "Scan avancé" refuse proprement (message + retour au menu) — le reste de l'outil marche.

---

## Installation

### Depuis GitHub (recommandé)

```bash
git clone https://github.com/Rooot3301/SYFFER.git
cd SYFFER
python -m venv .venv
```

**Activer le venv :**
- Linux / macOS : `source .venv/bin/activate`
- Windows PowerShell : `.venv\Scripts\Activate.ps1`
- Windows Git Bash : `source .venv/Scripts/activate`

Puis installer :

```bash
pip install -e .
```

### Alternative : environnement isolé via [pipx](https://pypa.github.io/pipx/)

```bash
pipx install git+https://github.com/Rooot3301/SYFFER.git
```

### Vérifier l'installation

```bash
syffer --help 2>/dev/null || syffer
```

La bannière + menu interactif doivent apparaître.

---

## Démarrage rapide

```bash
syffer
```

Navigation : flèches haut/bas, `Entrée` pour valider, `Ctrl+C` pour interrompre proprement.

**Premier test sans risque** — géolocalisation d'une IP publique (option 6) :
- Choisir "Géolocaliser une IP publique"
- Entrer `8.8.8.8`
- Résultat : pays / ville / région / coords / ISP

**Test nmap sur cible légale** — l'équipe nmap fournit `scanme.nmap.org` :
- "Scan avancé (nmap)" → "Quick (top 100 ports)"
- Cible : `scanme.nmap.org`
- Banner grabbing : oui

---

## Options du menu

| # | Option | Description | Requiert |
|---|---|---|---|
| 1 | **Capture de paquets** | Sniffe N paquets, filtre BPF optionnel, écrit `.pcap` horodaté | Npcap/root |
| 2 | **Scan du réseau (ARP)** | Scan ARP d'un CIDR, IP + MAC + vendor | Npcap/root |
| 3 | **Scan avancé (nmap)** | Port scan + fingerprinting (voir zoom) | nmap installé |
| 4 | **Infos réseau machine** | Hostname, IP locale, interfaces, MAC, MTU | — |
| 5 | **Adresse IP locale** | IP sortante détectée via socket UDP dummy | — |
| 6 | **Géolocaliser IP publique** | Lookup ip-api.com (pays, ville, ISP, coords) | Internet |
| 7 | **Détails paquet capturé** | Décodage complet d'un paquet capturé en session | Option 1 lancée avant |
| 8 | **Paramètres** | Toggle logs verbeux (DEBUG) | — |
| 9 | **Quitter** | | — |

Après chaque scan/capture, l'outil propose d'exporter en `txt` / `json` / `csv`.

---

## Zoom : Scan avancé nmap

Six profils accessibles depuis le sous-menu :

| Profil | Flags nmap | Cas d'usage |
|---|---|---|
| **Quick** | `-T4 -F` | Top 100 ports, rapide |
| **Full TCP** | `-T4 -p-` | Les 65535 ports TCP |
| **Service + Version** | `-T4 -sV` | Identifier services + versions |
| **OS Detection** | `-T4 -O -Pn` | Deviner l'OS distant _(admin requis)_ |
| **Aggressive** | `-T4 -A` | `-sV -O -sC --traceroute`, tout en un |
| **Custom** | `-T4` + checkbox | Cases à cocher : `-sV`, `-sC`, `-O`, `-Pn`, ports validés |

**Cibles acceptées** : IP, CIDR (`192.168.1.0/24`), hostname.

**Sécurité** — aucun flag nmap n'est saisissable en champ libre : le mode Custom passe par des cases à cocher, les ports par un parseur qui valide les bornes 1–65535. La ligne de commande est construite en `list[str]`, jamais `shell=True`.

**Banner grabbing passif** en complément (activable/désactivable) : `recv` TCP sans envoi de payload sur les ports détectés `open`, utile pour SSH/SMTP/FTP qui envoient une banner spontanément.

Le XML brut de nmap est toujours sauvegardé sous `extract/nmap-<cible>-<timestamp>.xml` pour retraitement.

---

## Exports

Après chaque opération, l'outil propose 4 choix :
- **Aucun** — pas d'export
- **txt** — rendu lisible humain
- **json** — sérialisation complète pour scripts
- **csv** — aplati (une ligne par port / host / paquet), idéal pour Excel/pandas

Sortie dans `extract/<nom>.{txt|json|csv}`. Le nom est sanitizé — pas de path traversal possible.

---

## Structure du projet

```
syffer/
├── core/           # Modules purs (aucune I/O utilisateur)
│   ├── models.py         # Dataclasses immuables (Interface, ScanResult, NmapScan, …)
│   ├── interfaces.py     # Interfaces réseau (psutil)
│   ├── network_info.py   # Hostname, IP locale, gateway
│   ├── network_scan.py   # Scan ARP (scapy)
│   ├── packet_capture.py # Capture + filtres BPF (scapy)
│   ├── geolocation.py    # Lookup ip-api.com
│   ├── nmap_tool.py      # Wrapper subprocess nmap (whitelist stricte)
│   ├── nmap_parser.py    # Parse XML nmap (xml.etree, stdlib)
│   ├── banner_grab.py    # Banner grabbing TCP passif
│   ├── port_scan.py      # Orchestrateur nmap + banner
│   └── external.py       # Wrapper ExternalTool générique
├── cli/            # Façade menu (rich + questionary)
│   ├── menu.py           # Boucle principale
│   ├── handlers.py       # Un handler par option
│   ├── submenu_nmap.py   # Sous-menu Scan avancé
│   ├── prompts.py        # Prompts validés
│   ├── display.py        # Rendu rich
│   └── session.py        # État de session (paquets, verbose, …)
├── reports/        # Export unifié
│   ├── formatters.py     # to_txt / to_json / to_csv par type
│   └── exporter.py       # Dispatcher
└── utils/          # Utilitaires
    ├── validation.py     # safe_filename, validate_cidr/ip/hostname/target/ports/bpf
    ├── paths.py          # safe_output_path (contre path traversal)
    └── logging_setup.py  # Config RichHandler

tests/              # 151 tests unitaires, mocks partout, aucun droit admin requis
extract/            # Sortie par défaut (gitignored)
docs/superpowers/   # Specs + plans d'implémentation
```

---

## Développement

### Installer en mode dev

```bash
pip install -e ".[dev]"
```

### Lancer la suite de tests

```bash
pytest
```

**151 tests** au total, tous mockés (scapy, psutil, requests, socket, subprocess). Aucun accès réseau réel ni droit admin requis en CI.

### Invariants d'architecture

- Pas de `input()` ni `print()` dans `syffer/core/*` ou `syffer/reports/*` — toute I/O utilisateur passe par `syffer/cli/*`.
- Toutes les fonctions `core/*` prennent leurs paramètres en argument et retournent des dataclasses immuables définies dans `models.py`.
- Sanitisation systématique des entrées qui touchent le système de fichiers ou le réseau.
- Ces règles rendent l'ajout d'une CLI à arguments (roadmap) trivial : le noyau est déjà découplé de la présentation.

---

## Roadmap

- **Phase 2** — Corrélation CVE : croiser les versions détectées par nmap `-sV` avec une base CVE (NVD API ou dataset local en cache).
- **Phase suivante** — Mode CLI à arguments (`syffer scan --target ... --profile quick`) en complément du menu interactif.

---

## Usage éthique

Syffer est un outil de **reconnaissance passive et active limitée** conçu pour l'audit et l'apprentissage. Ne l'utilisez que sur :

- Vos propres réseaux et machines.
- Des cibles pour lesquelles vous avez une **autorisation écrite** (bug bounty scope, mandat de test d'intrusion).
- Des cibles publiques explicitement mises à disposition : [scanme.nmap.org](https://scanme.nmap.org/), CTF, lab isolés.

Scanner sans autorisation est illégal dans la plupart des juridictions. Toute utilisation malveillante engage votre responsabilité.

---

## Licence

MIT — voir [LICENSE](LICENSE).

Créé par [ROOT3301](https://github.com/Rooot3301).
