# Syffer — Phase 0 : Fondations (design)

Date : 2026-09-24
Auteur : romain.varene@timci.com
Statut : validé (en cours de plan d'implémentation)

## 1. Contexte

Syffer est un petit outil CLI Python de recon réseau (capture de
paquets + scan ARP + infos réseau + géolocalisation IP), écrit dans
un unique fichier `Syffer.py` de ~190 lignes. Le code souffre de
plusieurs défauts bloquants :

- L'option "Scan du réseau" plante systématiquement : appel
  `generate_report(response)` avec un argument alors que la fonction
  en attend deux (crash `TypeError` garanti).
- La dépendance `netifaces==0.11.0` ne s'installe pas sur Python
  3.12 sous Windows (nécessite MSVC Build Tools, projet abandonné).
- Le menu ne boucle pas : une seule action par lancement, donc
  l'option "Afficher les détails d'un paquet" est structurellement
  inutilisable (les paquets capturés sont perdus au lancement
  suivant).
- Pas de séparation logique métier / I/O : chaque fonction contient
  à la fois du réseau, des `print()` colorés, et des `input()`.
  Impossible à tester, impossible à réutiliser depuis une future CLI
  à arguments.
- `report_name` vient directement de `input()` et est concaténé au
  chemin de sortie sans validation (path traversal possible).
- Dépendances toutes obsolètes (`scapy==2.4.5` de 2020,
  `requests==2.26.0` avec CVE corrigées depuis).

Phase 0 = fondations : on remet l'outil sur pied et on l'architecture
pour que les phases suivantes (scan de ports, fingerprinting,
corrélation CVE) se branchent sans refonte.

## 2. Objectifs Phase 0

Cette phase est explicitement **recon uniquement** — pas
d'exploitation active, pas de Metasploit, pas de brute-force. Nmap
(pour Phase 1) et autres outils externes seront intégrés via un
pattern de wrapper préparé dès Phase 0.

Fournir un socle Syffer qui :

1. Corrige tous les bugs et lacunes ci-dessus.
2. S'installe réellement sur Windows / Linux / macOS avec Python 3.12+
   sans compilateur C.
3. Présente un menu interactif propre (navigation fléchée, tableaux
   colorés, boucle jusqu'à "Quitter") comme interface principale.
4. Sépare strictement logique métier (`core/*`) et présentation
   (`cli/menu.py`), pour qu'une CLI à arguments (Phase suivante)
   puisse être ajoutée sans réécrire le noyau.
5. Ajoute les filtres BPF à la capture de paquets.
6. Ajoute un export unifié JSON / CSV / TXT.
7. Ajoute un logging structuré (mode debug activable via le menu).
8. Inclut un pattern "wrapper d'outil externe" (`core/external.py`)
   pour préparer Phase 1 (nmap).
9. Est testable en CI sans droits admin (mocks scapy).

**Hors scope Phase 0** :

- Scan de ports TCP (Phase 1).
- Fingerprinting OS/services (Phase 1).
- Corrélation CVE (Phase 2).
- CLI à arguments type `syffer scan --range ...` (Phase suivante,
  greffée par-dessus les mêmes fonctions core).
- Toute forme d'exploitation active.

## 3. Approches considérées

Trois approches ont été discutées avant validation :

- **A. Patch minimal** — corriger les bugs sur place dans
  `Syffer.py`. Rejeté : ne résout pas la dette structurelle, ne
  prépare rien pour Phase 1.
- **B. CLI à arguments d'abord** (argparse/click, sous-commandes
  `syffer scan …`). Rejeté par l'utilisateur pour Phase 0 : la
  demande est "menu interactif d'abord, CLI ensuite".
- **C. Package modulaire + menu interactif comme façade
  (retenue)** — noyau réutilisable dans `core/`, menu comme façade,
  CLI à arguments greffée plus tard sans refonte.

## 4. Architecture

```
syffer/
  __init__.py
  __main__.py              # python -m syffer -> menu.run()
  config.py                # constantes (dossier extract, timeouts, versions)
  cli/
    __init__.py
    menu.py                # boucle principale (questionary + rich)
    prompts.py             # helpers de saisie (CIDR, BPF, index, nom fichier)
    display.py             # rendu rich (tableaux, bannière, formatage résultats)
  core/
    __init__.py
    interfaces.py          # liste des interfaces (psutil)
    network_info.py        # infos réseau machine (IP locale, hostname, gateways)
    packet_capture.py      # capture + filtres BPF (scapy)
    network_scan.py        # scan ARP (scapy)
    geolocation.py         # lookup ip-api (requests)
    external.py            # wrapper d'outil externe (préparé pour nmap Phase 1)
    models.py              # dataclasses partagées (Host, PacketSummary, ScanResult...)
  reports/
    __init__.py
    exporter.py            # dispatch selon format (txt/json/csv)
    formatters.py          # sérialisation par type de résultat
  utils/
    __init__.py
    logging_setup.py       # config logging + RichHandler
    validation.py          # sanitisation (nom fichier, CIDR, BPF)
    paths.py               # résolution du dossier extract/ + noms uniques
tests/
  test_validation.py
  test_exporter.py
  test_network_scan.py     # mocks scapy
  test_packet_capture.py   # mocks scapy
  test_interfaces.py       # mocks psutil
  test_geolocation.py      # mocks requests
extract/                    # gitignored, sortie des rapports
pyproject.toml              # packaging, entry point `syffer`
README.md                   # mis à jour (install, usage, prérequis Npcap/root)
requirements.txt            # (compat pip install -r ; miroir de pyproject)
.gitignore
```

**Règles d'architecture (invariants)** :

- Aucun `input()` ni `print()` dans `core/*` ou `reports/*`.
- Chaque fonction `core/*` prend ses paramètres en argument
  (chaînes, ints, dataclasses) et retourne des dataclasses ou
  listes de dataclasses définies dans `core/models.py`.
- La façade `cli/menu.py` ne fait que : afficher, demander des
  paramètres via `prompts.py`, appeler `core/*`, afficher le
  résultat via `display.py`, éventuellement passer au dispatcher
  d'export `reports/exporter.py`.
- Cette discipline garantit qu'un futur `cli/args.py` (Phase
  suivante) réutilisera les mêmes appels core sans duplication.

## 5. Composants détaillés

### 5.1 `core/models.py`

Dataclasses immuables (`@dataclass(frozen=True)`) pour les résultats
échangés entre core, exporter et façade :

- `Interface(name, addresses: list[InterfaceAddress], is_up, mac, mtu)`
- `InterfaceAddress(family, address, netmask, broadcast)`
- `NetworkInfo(hostname, local_ip, default_gateway, interfaces: list[Interface])`
- `PacketSummary(index, timestamp, summary, src, dst, protocol, length)`
- `CaptureResult(pcap_path, packets: list[PacketSummary], bpf_filter)`
- `Host(ip, mac, vendor: str | None)`
- `ScanResult(cidr, started_at, duration_s, hosts: list[Host])`
- `GeoInfo(ip, country, city, region, lat, lon, isp)`

Le paquet scapy brut (`packets[i]`) est conservé séparément dans
la session menu pour l'option "détails d'un paquet" (voir 5.4). Les
dataclasses restent sérialisables (JSON/CSV) sans dépendre de scapy.

### 5.2 `core/interfaces.py` et `core/network_info.py`

Remplacent complètement `netifaces` par `psutil` :

- `list_interfaces() -> list[Interface]` via `psutil.net_if_addrs()`
  + `psutil.net_if_stats()`.
- `get_network_info() -> NetworkInfo` combine hostname (`socket`),
  IP locale (résolue via socket UDP dummy vers 8.8.8.8, sans
  paquet réellement envoyé), gateway par défaut (`psutil` ou
  fallback plateforme), et interfaces.

Rationale : `psutil` a des wheels précompilées pour toutes les
plateformes et Python 3.12, résout le blocage d'installation
netifaces.

### 5.3 `core/packet_capture.py`

- `capture(count: int, bpf_filter: str | None, iface: str | None,
  timeout: int | None) -> tuple[CaptureResult, list[Packet]]`
- Utilise `scapy.sniff(count=..., filter=..., iface=..., timeout=...)`.
- Le filtre BPF est validé par `utils.validation.validate_bpf` (voir
  5.9) avant appel.
- Retourne `(CaptureResult, packets_bruts)` : le premier pour
  export/affichage, le second gardé en mémoire de session pour
  `packet.show()`.
- Ecrit le pcap via `wrpcap` dans le dossier `extract/` avec un nom
  timestampé (`capture-YYYYMMDD-HHMMSS.pcap`).

### 5.4 `core/network_scan.py`

- `arp_scan(cidr: str, timeout: int = 3) -> ScanResult`
- Valide `cidr` via `ipaddress.ip_network(cidr, strict=False)` avant
  d'envoyer les paquets (fini le crash sur saisie invalide).
- Construit et envoie `Ether(dst='ff:...') / ARP(pdst=cidr)` via
  `srp`.
- Enrichit chaque `Host` avec le vendor MAC si possible (lookup
  local via `scapy.data.MANUFDB` si disponible, sinon vendor=None —
  pas d'appel réseau, pas de nouvelle dépendance).

### 5.5 `core/geolocation.py`

- `lookup(ip: str, timeout: int = 5) -> GeoInfo`
- `requests.get('http://ip-api.com/json/{ip}', timeout=timeout)`.
- Lève une exception typée `GeolocationError` si status ≠ 200 ou
  `status == 'fail'` dans la réponse.
- Utilise HTTPS uniquement si la version gratuite le permet ; sinon
  garde HTTP (l'API ip-api.com gratuite est HTTP).

### 5.6 `core/external.py` (préparation Phase 1)

Pattern générique pour envelopper un binaire externe, préparé mais
non exploité en Phase 0 :

```python
class ExternalTool:
    def __init__(self, name: str, min_version: str | None = None): ...
    def available(self) -> bool: ...        # shutil.which + version check
    def run(self, args: list[str], timeout: int) -> subprocess.CompletedProcess: ...
```

Aucun outil concret (nmap, tcpdump…) n'est instancié en Phase 0.
Le module et un test unitaire existent uniquement pour cadrer
l'interface que Phase 1 consommera. Ça évite qu'on invente une
autre convention plus tard sous pression.

### 5.7 `cli/menu.py`

Boucle principale :

```
while True:
    action = questionary.select("Menu principal", choices=[
        "Capture de paquets",
        "Scan du réseau (ARP)",
        "Informations réseau de la machine",
        "Adresse IP locale",
        "Géolocaliser une IP publique",
        "Détails d'un paquet capturé",
        "Paramètres (logs, dossier de sortie)",
        "Quitter",
    ]).ask()
    dispatch(action)
```

- L'état de session (`captured_packets: list[Packet]`,
  `last_capture_result: CaptureResult | None`, `settings`) est un
  objet passé aux handlers.
- Chaque handler : demande les paramètres via `prompts.py`, appelle
  le module `core/*` concerné, capture les exceptions applicatives
  (`ValueError`, `PermissionError`, `GeolocationError`, `OSError`
  scapy), affiche via `display.py`, propose l'export.
- L'option "Détails d'un paquet" est enfin fonctionnelle car la
  capture précédente reste en mémoire tant que le menu tourne.
- L'option "Paramètres" permet d'activer le mode verbeux
  (`logging.DEBUG`) et de changer le dossier de sortie pour la
  session courante.

### 5.8 `reports/exporter.py`

- `export(result, fmt: Literal['txt', 'json', 'csv'], out_path:
  Path) -> Path`
- Dispatch sur `formatters.py` selon le type du résultat
  (`CaptureResult`, `ScanResult`, `NetworkInfo`, `GeoInfo`).
- Le nom de fichier est produit par `utils.paths.safe_output_path`
  qui : sanitize le nom demandé (`utils.validation.safe_filename` —
  slug alphanumérique + `-_.`, refuse `..`, refuse séparateurs),
  ajoute l'extension, garantit que le chemin final reste sous
  `extract/`. Fini le path traversal.

### 5.9 `utils/validation.py`

- `safe_filename(name: str) -> str` : conserve `[A-Za-z0-9-_.]`,
  refuse chaîne vide, refuse `..`, tronque à 100 caractères.
- `validate_cidr(cidr: str) -> ipaddress.IPv4Network` : wrap
  `ipaddress.ip_network(cidr, strict=False)`, lève `ValueError`
  clair.
- `validate_ip(ip: str) -> str` : `ipaddress.ip_address(ip)`.
- `validate_bpf(expr: str) -> str` : validation syntaxique
  best-effort via `scapy.arch.common.compile_filter` si disponible
  ; sinon whitelist regex conservatrice (mots-clés BPF connus +
  chiffres + ponctuation autorisée). Renvoie l'expression telle
  quelle si OK, lève `ValueError` sinon.

### 5.10 `utils/logging_setup.py`

- `configure(verbose: bool)` : root logger avec `RichHandler`,
  niveau `DEBUG` si `verbose` sinon `INFO`. Les modules core
  utilisent `logging.getLogger(__name__)` — jamais `print()`.

## 6. Flux de données (exemple : scan ARP + export)

1. `menu.run()` → utilisateur choisit "Scan du réseau (ARP)".
2. `prompts.ask_cidr()` demande la plage, boucle jusqu'à ce que
   `validate_cidr` accepte.
3. `network_scan.arp_scan(cidr, timeout=3)` s'exécute (peut lever
   `PermissionError` si pas admin/root → catch dans menu, message
   propre).
4. `display.render_scan(result)` affiche un `rich.Table` avec IP /
   MAC / vendor.
5. `prompts.ask_export()` : format (aucun / txt / json / csv) + nom
   de fichier (validé par `safe_filename`).
6. Si export choisi : `exporter.export(result, fmt, path)` écrit
   sous `extract/`, affiche le chemin final.
7. Retour à la boucle de menu.

## 7. Gestion d'erreurs

Politique simple à deux niveaux :

- **Erreurs attendues** (`ValueError` de validation,
  `PermissionError` si pas admin, `GeolocationError`, timeouts
  scapy/requests) : catch dans les handlers de `cli/menu.py`,
  affichage rich rouge d'une ligne, retour au menu. La stack trace
  passe en `logger.debug` (visible uniquement en mode verbeux).
- **Erreurs inattendues** : catch au top-level `__main__.py`,
  message "erreur interne, activez le mode verbeux pour plus de
  détails", exit 1.

Cas particuliers documentés dans le README :

- Sous Windows, scapy nécessite Npcap ; on détecte l'absence
  (`OSError` avec message spécifique) et on renvoie vers la doc
  d'installation.
- Sous Linux/macOS, capture et scan ARP nécessitent des droits
  root/CAP_NET_RAW ; message d'erreur explicite.

## 8. Tests

Suite `pytest` visant les invariants d'architecture, pas des tests
end-to-end réseau (qui nécessiteraient des droits admin et un
environnement réel) :

- `test_validation.py` : `safe_filename`, `validate_cidr`,
  `validate_ip`, `validate_bpf` — cas nominaux et attaques (path
  traversal, CIDR invalide, injection BPF).
- `test_exporter.py` : export d'un `ScanResult` factice en txt /
  json / csv, vérifier que le chemin final reste sous `extract/`
  et que le contenu est correct.
- `test_network_scan.py` : mock `scapy.srp` pour retourner des
  paires factices, vérifier construction de `ScanResult` +
  enrichissement vendor.
- `test_packet_capture.py` : mock `scapy.sniff` + `wrpcap`,
  vérifier appels avec filtre BPF + retour `CaptureResult`.
- `test_interfaces.py` : mock `psutil.net_if_addrs` /
  `net_if_stats`, vérifier mapping vers `Interface`.
- `test_geolocation.py` : mock `requests.get`, cas succès + `fail`
  + timeout.
- `test_external.py` : mock `shutil.which` + `subprocess.run`,
  vérifier `available()` et `run()` (préparation Phase 1).

CI : GitHub Actions matrix Python 3.10 / 3.11 / 3.12, Ubuntu /
Windows / macOS, `pip install -e .[dev]` + `pytest`.

## 9. Packaging

`pyproject.toml` avec build-system `hatchling`, entry point
console :

```toml
[project.scripts]
syffer = "syffer.__main__:main"
```

Installation :

```
pip install -e .        # dev
pip install .           # user
pipx install .          # isolé
```

`requirements.txt` reste présent (miroir des dépendances runtime)
pour compat `pip install -r`.

**Dépendances runtime** :
- `scapy>=2.5,<3`
- `psutil>=5.9,<7`
- `requests>=2.32,<3`   (corrige CVE 2.26.0)
- `rich>=13,<14`
- `questionary>=2,<3`

**Dépendances retirées** :
- `netifaces` (remplacé par `psutil`)
- `colorama` (remplacé par `rich`)

**Dépendances dev** :
- `pytest`, `pytest-mock`, `pytest-cov`

## 10. README (mise à jour)

Contenu réécrit pour couvrir :

- Prérequis par OS (Python 3.10+, Npcap sous Windows, droits root
  sous Linux/macOS pour capture/ARP).
- Installation via `pip install -e .` ou `pipx install .`.
- Usage : `syffer` lance le menu.
- Description des options du menu.
- Roadmap explicite : Phase 1 (port scan + fingerprinting via
  nmap), Phase 2 (corrélation CVE).
- Note d'usage : outil de recon uniquement, à utiliser sur des
  réseaux dont on a l'autorisation.

## 11. Migration / compat ascendante

Rupture assumée avec la version actuelle (unique fichier
`Syffer.py`) :

- L'ancien `Syffer.py` est supprimé.
- Le point d'entrée est désormais `syffer` (console script) ou
  `python -m syffer`.
- Le contenu du dossier `extract/` de l'utilisateur est préservé
  (`.gitkeep` conservé, `extract/*` en `.gitignore`).

## 12. Livrables Phase 0

- Structure de package complète telle que définie section 4.
- Tous les tests unitaires listés section 8, verts en CI.
- README mis à jour.
- `pyproject.toml` fonctionnel (`pip install -e .` installe `syffer`).
- L'outil lancé via `syffer` boucle jusqu'à Quitter, les 7 options
  du menu fonctionnent (dont "Détails d'un paquet" après capture
  dans la même session).
- Aucun bug de la liste section 1 ne subsiste.
- Un CHANGELOG.md initial documente les breaking changes.

## 13. Prochaine étape

Invocation du skill `superpowers:writing-plans` pour produire le
plan d'implémentation détaillé (tâches, ordre, points de revue) à
partir de ce design.
