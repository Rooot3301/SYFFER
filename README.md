# Syffer - Outil de Capture de Paquets et de Scan Réseau

░██████╗██╗░░░██╗███████╗███████╗███████╗██████╗░  ██████╗░██╗░░░██╗
██╔════╝╚██╗░██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗  ██╔══██╗╚██╗░██╔╝
╚█████╗░░╚████╔╝░█████╗░░█████╗░░█████╗░░██████╔╝  ██████╦╝░╚████╔╝░
░╚═══██╗░░╚██╔╝░░██╔══╝░░██╔══╝░░██╔══╝░░██╔══██╗  ██╔══██╗░░╚██╔╝░░
██████╔╝░░░██║░░░██║░░░░░██║░░░░░███████╗██║░░██║  ██████╦╝░░░██║░░░
╚═════╝░░░░╚═╝░░░╚═╝░░░░░╚═╝░░░░░╚══════╝╚═╝░░╚═╝  ╚═════╝░░░░╚═╝░░░

██████╗░░█████╗░░█████╗░████████╗██████╗░██████╗░░█████╗░░░███╗░░
██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝╚════██╗╚════██╗██╔══██╗░████║░░
██████╔╝██║░░██║██║░░██║░░░██║░░░░█████╔╝░█████╔╝██║░░██║██╔██║░░
██╔══██╗██║░░██║██║░░██║░░░██║░░░░╚═══██╗░╚═══██╗██║░░██║╚═╝██║░░
██║░░██║╚█████╔╝╚█████╔╝░░░██║░░░██████╔╝██████╔╝╚█████╔╝███████╗
╚═╝░░╚═╝░╚════╝░░╚════╝░░░░╚═╝░░░╚═════╝░╚═════╝░░╚════╝░╚══════╝

## Description
Syffer est un outil simple en ligne de commande qui permet de capturer des paquets réseau et de scanner les appareils connectés au réseau local. Il offre également des fonctionnalités pour obtenir des informations sur le réseau de votre machine, l'adresse IP locale, la localisation d'une adresse IP publique et afficher les détails des paquets capturés.

## Installation
1. Assurez-vous d'avoir Python 3.x installé sur votre système.
2. Clonez ce référentiel GitHub vers votre machine locale.
3. Installez les dépendances requises en exécutant la commande suivante : pip install -r requirements.txt

## Utilisation
1. Exécutez le script `Syffer.py` pour lancer le programme.
2. Le menu principal s'affiche, suivez les instructions pour sélectionner l'option souhaitée.
3. Suivez les instructions spécifiques à chaque option pour capturer des paquets, scanner le réseau, obtenir des informations réseau, etc.
4. Les rapports de capture de paquets et de scan réseau seront enregistrés dans le répertoire "extract" du projet.

## Options du Menu
1. **Capture de Paquets :** Capture et affiche les 10 derniers paquets réseau. Enregistre également les paquets capturés dans un fichier PCAP et génère un rapport TXT avec les détails de la capture.

2. **Scan du Réseau :** Scanne le réseau local pour détecter les appareils connectés. Affiche les adresses IP et les adresses MAC des appareils détectés. Enregistre également les résultats du scan dans un rapport TXT.

3. **Obtenir les Informations Réseau de la Machine :** Affiche les informations réseau de votre machine, telles que les adresses IP, les adresses MAC, les interfaces réseau, etc.

4. **Obtenir l'Adresse IP Locale de la Machine :** Affiche l'adresse IP locale de votre machine.

5. **Obtenir la Localisation d'une Adresse IP Publique :** Obtient la localisation (pays, ville, région, latitude, longitude) d'une adresse IP publique en utilisant l'API IP-API.

6. **Afficher les Détails d'un Paquet :** Affiche les détails d'un paquet capturé spécifique en fonction de l'index.

7. **Quitter :** Quitte le programme.

## Remarques
- Certaines options, telles que la capture de paquets, peuvent nécessiter des permissions root/administrateur pour accéder à certaines fonctionnalités réseau.

## Auteur
Ce projet a été créé par ROOT3301.

## Licence
Ce projet est sous licence MIT.


