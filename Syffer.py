import os
from scapy.all import *
from colorama import init, Fore
import netifaces as ni
import socket
import requests

# Initialisation de colorama
init()

# Créer le répertoire "extract" s'il n'existe pas déjà
os.makedirs("extract", exist_ok=True)

# Variable globale pour stocker les paquets capturés
captured_packets = []

# Fonction pour capturer les paquets réseau
def capture_packets():
    global captured_packets
    try:
        captured_packets = sniff(count=10)  # Capturer 10 paquets
    except Exception as e:
        print("Une erreur s'est produite lors de la capture des paquets :", e)

    # Traiter les paquets capturés
    for packet in captured_packets:
        print(Fore.GREEN + packet.summary())  # Afficher le résumé du paquet en vert
    print(Fore.RESET)  # Réinitialiser la couleur du texte

    # Enregistrer les paquets capturés dans un fichier PCAP
    pcap_file = os.path.join("extract", "captured_packets.pcap")
    wrpcap(pcap_file, captured_packets)

    # Générer le rapport de capture de paquets
    generate_report(captured_packets, pcap_file)

# Fonction pour scanner les appareils du réseau
def scan_network():
    target_ip = input("Entrez la plage d'IP à scanner (par exemple, 192.168.1.0/24) : ")
    arp_scan = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_scan
    response = srp(arp_request_broadcast, timeout=3, verbose=0)[0]

    # Traiter les résultats du scan
    print("Scan du réseau en cours...\n")
    print(Fore.CYAN + "IP\t\t\tAdresse MAC")
    print("-----------------------------------------")
    for sent, received in response:
        print(received.psrc + "\t\t" + received.hwsrc)
    print("-----------------------------------------")
    print(Fore.RESET)  # Réinitialiser la couleur du texte

    # Générer le rapport du scan du réseau
    generate_report(response)

# Fonction pour obtenir les informations réseau de la machine
def get_network_info():
    interfaces = ni.interfaces()
    for i, interface in enumerate(interfaces):
        print(f"Interface {i+1}: {interface}")
        addresses = ni.ifaddresses(interface)
        for addr_type, info in addresses.items():
            print(f"   {addr_type}: {info}")
        print()

# Fonction pour obtenir l'adresse IP locale de la machine
def get_local_ip():
    local_ip = socket.gethostbyname(socket.gethostname())
    print(f"L'adresse IP locale de la machine est : {local_ip}")

# Fonction pour obtenir la localisation d'une adresse IP publique
def get_ip_location():
    ip_address = input("Entrez l'adresse IP publique que vous souhaitez localiser : ")
    url = f"http://ip-api.com/json/{ip_address}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        if data["status"] == "success":
            print("\nInformations de localisation pour l'adresse IP :", ip_address)
            print("Pays :", data.get("country", "N/A"))
            print("Ville :", data.get("city", "N/A"))
            print("Région :", data.get("regionName", "N/A"))
            print("Latitude :", data.get("lat", "N/A"))
            print("Longitude :", data.get("lon", "N/A"))
        else:
            print(f"L'adresse IP {ip_address} n'a pas pu être localisée.")
    else:
        print(f"Impossible d'obtenir les informations de localisation pour l'adresse IP {ip_address}.")

# Fonction pour afficher les détails d'un paquet sélectionné
def show_packet_details():
    index = input("Entrez l'index du paquet que vous souhaitez afficher : ")
    if index.isdigit():
        index = int(index)
        if 0 <= index < len(captured_packets):
            print("\nDétails du paquet :")
            print(captured_packets[index].show())
        else:
            print("Index de paquet invalide.")
    else:
        print("Veuillez saisir un nombre entier valide.")

# Fonction pour générer le rapport
def generate_report(data, pcap_file):
    report_name = input("Entrez un nom pour exporter votre fichier (sans extension) : ")
    report_file = os.path.join("extract", report_name + ".txt")

    with open(report_file, "w") as f:
        # Écrire les informations de la capture de paquets dans le rapport TXT
        f.write("Informations de la capture de paquets :\n")
        f.write("-----------------------------\n")
        f.write(f"Nombre de paquets capturés : {len(data)}\n")
        f.write(f"Le fichier PCAP est enregistré sous : {pcap_file}\n")
        f.write("-----------------------------\n\n")
        # Écrire les paquets capturés dans le rapport TXT
        f.write("Détails des paquets capturés :\n")
        f.write("-----------------------------\n")
        for i, packet in enumerate(data, start=1):
            f.write(f"Paquet {i} :\n")
            f.write(str(packet) + "\n")
            f.write("-----------------------------\n")

    print("Rapport généré avec succès : " + report_file)

# Logo en art ASCII
logo = r"""

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
"""

# Afficher le logo
print(Fore.YELLOW + logo)
print(Fore.CYAN + "Créé par ROOT3301, pour une expérience optimale, les permissions root sont requises.")
print(Fore.RESET)  # Réinitialiser la couleur du texte

# Obtenir l'entrée de l'utilisateur pour la sélection d'une option
print("Veuillez choisir une option :")
print(Fore.YELLOW + "1. Capture de Paquets")
print("2. Scan du Réseau")
print("3. Obtenir les Informations Réseau de la Machine")
print("4. Obtenir l'Adresse IP Locale de la Machine")
print("5. Obtenir la Localisation d'une Adresse IP Publique")
print("6. Afficher les Détails d'un Paquet")
print("7. Quitter")
option = input("Entrez le numéro de l'option : ")
if option.isdigit():
    option = int(option)
else:
    print("Veuillez saisir un nombre entier valide.")
    exit()

# Exécuter l'option choisie
if option == 1:
    capture_packets()
elif option == 2:
    scan_network()
elif option == 3:
    get_network_info()
elif option == 4:
    get_local_ip()
elif option == 5:
    get_ip_location()
elif option == 6:
    show_packet_details()
elif option == 7:
    print("Fermeture...")
else:
    print("Option invalide sélectionnée.")










