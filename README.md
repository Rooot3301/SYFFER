# Syffer

Outil CLI de recon réseau : capture de paquets, scan ARP, informations
réseau, géolocalisation d'IP. **Recon uniquement** — pas d'exploitation
active.

```
   _______     ________ ______ ______ ______
  / ____/ |   / / ____/ ____/ ____/ ____/ __ \
 (__  \| | / / /_  /_  /_   /_   / /_/ /
_____/ | |/ / __/ __/ __/ __/ _, _/
     /  |___/_/   /_/   /_/   /_/ |_|
```

## Prérequis

- Python ≥ 3.10 (testé 3.10 / 3.11 / 3.12).
- **Windows** : [Npcap](https://npcap.com/) installé pour la capture
  de paquets et le scan ARP.
- **Linux / macOS** : la capture et le scan ARP nécessitent
  `CAP_NET_RAW` ou d'être lancés en root.
- **Optionnel** : [nmap](https://nmap.org/download.html) ≥ 7.90 pour
  l'option "Scan avancé (nmap)".

## Installation

Depuis le dossier du projet :

```bash
pip install -e .
```

Ou en environnement isolé via [pipx](https://pypa.github.io/pipx/) :

```bash
pipx install .
```

## Utilisation

```bash
syffer
```

Le menu interactif s'affiche. Utilisez les flèches pour naviguer,
Entrée pour valider. Menu :

1. **Capture de paquets** — sniffe N paquets, filtre BPF optionnel,
   écrit un `.pcap` horodaté dans `extract/`.
2. **Scan du réseau (ARP)** — scan ARP d'un CIDR, affiche IP / MAC /
   vendor.
3. **Scan avancé (nmap)** — port scan + fingerprinting via wrapper
   nmap : 5 profils prédéfinis (Quick, Full TCP, Service+Version, OS
   Detection, Aggressive) + mode Custom (ports + toggles). Banner
   grabbing TCP passif optionnel en complément. Le XML brut de nmap
   est sauvegardé sous `extract/nmap-*.xml`. **Requiert nmap
   installé** ([nmap.org/download](https://nmap.org/download.html)) ;
   l'option refuse proprement si le binaire est absent. OS detection
   et scan ARP demandent des droits root/admin.
4. **Informations réseau de la machine** — hostname, IP locale,
   interfaces (via psutil).
5. **Adresse IP locale**.
6. **Géolocaliser une IP publique** — via ip-api.com.
7. **Détails d'un paquet capturé** — après une capture dans la même
   session, affiche les détails complets d'un paquet par son index.
8. **Paramètres** — activer/désactiver les logs verbeux.
9. **Quitter**.

Les rapports (txt / json / csv) sont proposés à l'export après chaque
opération et enregistrés dans `extract/`.

## Roadmap

- **Phase 2** — corrélation CVE : croiser les versions détectées en
  Phase 1 avec une base CVE (NVD ou dataset local).
- **Phase suivante** — mode CLI à arguments (`syffer scan --range
  ...`) en complément du menu.

## Usage éthique

Syffer est un outil de recon à utiliser uniquement sur des réseaux
dont vous êtes propriétaire ou pour lesquels vous avez une
autorisation écrite. Toute utilisation malveillante est de votre
responsabilité.

## Auteur

Créé par ROOT3301. Sous licence MIT.
