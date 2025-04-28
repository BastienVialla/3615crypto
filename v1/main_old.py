import os
import base64
# import json
import secrets
# import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asymm_padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption

try:
    # Import des algorithmes post-quantiques via pqcrypto
    from pqcrypto.kem.kyber import (
        Kyber512, Kyber768, Kyber1024,
        generate_keypair as kyber_generate_keypair,
        encrypt as kyber_encrypt
    )
    
    PQ_AVAILABLE = True
except ImportError:
    PQ_AVAILABLE = False
    print("Note: pqcrypto n'est pas installé. Les algorithmes post-quantiques ne sont pas disponibles.")
    print("Pour l'installer, exécutez : pip install pqcrypto")

WIDTH = 40
HEXA_CHARS = '0123456789abcdef'

class EncryptionApp:
    def __init__(self):
        self.algorithms = ["AES", "RSA", "ECC"]
        if PQ_AVAILABLE:
            self.algorithms.extend(["KYBER"])#, "DILITHIUM"
        self.key_sizes = {
            "AES": [128, 192, 256],
            "RSA": [1024, 2048, 3072, 4096],
            "ECC": ["SECP256R1", "SECP384R1", "SECP521R1"]
        }
        if PQ_AVAILABLE:
            self.key_sizes.update({
                "KYBER": ["KYBER512", "KYBER768", "KYBER1024"],
                # "DILITHIUM": ["DILITHIUM2", "DILITHIUM3", "DILITHIUM5"]
            })
        
        self.output_formats = ["base64", "hex", "base10", "carte perforée"]
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        self.clear_screen()
        print("=" * WIDTH)
        print("               3615 CRYPTO")
        print("-" * WIDTH)
        if PQ_AVAILABLE:
            print(" - post-quantique disponible")
        else:
            print(" - post-quantique non disponible")
        print(" - entrer :q: pour quitter")
        print("=" * WIDTH)
        print()

    def get_user_input(self):
        self.print_header()
        
        # Message à chiffrer
        message = input("Entrez le message à chiffrer: ")
        if message == ':q:':
            return message, None, None, None
        
        # Choix de l'algorithme
        print("\nAlgorithmes disponibles:")
        for i, algo in enumerate(self.algorithms, 1):
            print(f"{i}. {algo}")
        
        while True:
            try:
                max_choice = len(self.algorithms)
                choice = int(input(f"\nChoisissez un algorithme (1-{max_choice}): "))
                if 1 <= choice <= max_choice:
                    algorithm = self.algorithms[choice-1]
                    break
                else:
                    print(f"Choix invalide. Veuillez choisir entre 1 et {max_choice}.")
            except ValueError:
                print("Veuillez entrer un nombre.")
        
        # Choix de la taille de clé
        print(f"\nTailles de clé disponibles pour {algorithm}:")
        for i, size in enumerate(self.key_sizes[algorithm], 1):
            print(f"{i}. {size}")
        
        while True:
            try:
                choice = int(input(f"\nChoisissez une taille de clé (1-{len(self.key_sizes[algorithm])}): "))
                if 1 <= choice <= len(self.key_sizes[algorithm]):
                    key_size = self.key_sizes[algorithm][choice-1]
                    break
                else:
                    print(f"Choix invalide. Veuillez choisir entre 1 et {len(self.key_sizes[algorithm])}.")
            except ValueError:
                print("Veuillez entrer un nombre.")
        
        # Choix du format de sortie
        print("\nFormats d'encodage disponibles:")
        for i, fmt in enumerate(self.output_formats, 1):
            print(f"{i}. {fmt}")
        
        while True:
            try:
                max_choice = len(self.output_formats)
                choice = int(input(f"\nChoisissez un format d'encodage (1-{max_choice}): "))
                if 1 <= choice <= max_choice:
                    output_format = self.output_formats[choice-1]
                    break
                else:
                    print(f"Choix invalide. Veuillez choisir entre 1 et {max_choice}.")
            except ValueError:
                print("Veuillez entrer un nombre.")
        
        return message, algorithm, key_size, output_format

    def encrypt_aes(self, message, key_size):
        # Générer une clé AES de la taille spécifiée
        key = os.urandom(key_size // 8)  # Convertir bits en octets
        
        # Générer un IV (vecteur d'initialisation)
        iv = os.urandom(16)  # AES utilise un bloc de 16 octets
        
        # Préparer le message (padding)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        # Chiffrer le message
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Concaténer l'IV et le texte chiffré pour le déchiffrement ultérieur
        encrypted = iv + ciphertext
        
        return encrypted, {"clé": key}

    def encrypt_rsa(self, message, key_size):
        # Générer une paire de clés RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        public_key = private_key.public_key()
        
        # Chiffrer le message avec la clé publique
        encrypted = public_key.encrypt(
            message.encode(),
            asymm_padding.OAEP(
                mgf=asymm_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Sérialiser les clés pour l'affichage
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        return encrypted, {"cle secrete": private_key_pem, "cle publique": public_key_pem}

    def encrypt_ecc(self, message, curve_name):
        # Convertir le nom de courbe en paramètre approprié
        curve_map = {
            "SECP256R1": ec.SECP256R1(),
            "SECP384R1": ec.SECP384R1(),
            "SECP521R1": ec.SECP521R1()
        }
        curve = curve_map[curve_name]
        
        # Générer une paire de clés ECC
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        
        # Pour ECC, nous utilisons un chiffrement hybride (ECIES simplifié)
        # Générer une clé AES temporaire
        aes_key = os.urandom(32)  # Clé AES-256
        iv = os.urandom(16)
        
        # Chiffrer le message avec AES
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Dériver une clé partagée (simulée ici pour simplifier)
        # En pratique, on échangerait des clés avec ECDH
        shared_key = secrets.token_bytes(32)
        
        # Sérialiser les clés pour l'affichage
        private_key_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        )
        
        public_key_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        
        # Concaténer IV et texte chiffré
        encrypted = iv + ciphertext
        
        return encrypted, {
            "clé secrète": private_key_pem, 
            "clé publique": public_key_pem,
            #"clé partagé": shared_key
        }
        
    def encrypt_kyber(self, message, kyber_variant):
        if not PQ_AVAILABLE:
            raise ImportError("Module pqcrypto non installé!")
        
        # Choisir la variante de Kyber
        if kyber_variant == "KYBER512":
            variant = Kyber512
        elif kyber_variant == "KYBER768":
            variant = Kyber768
        elif kyber_variant == "KYBER1024":
            variant = Kyber1024
        
        # Générer les clés
        public_key, private_key = kyber_generate_keypair(variant)
        
        # Kyber est un système KEM (Key Encapsulation Mechanism)
        # qui produit une clé secrète partagée et un texte chiffré
        shared_secret, ciphertext = kyber_encrypt(public_key, variant)
        
        # Utiliser cette clé partagée pour chiffrer le message avec AES
        # Cette approche hybride est courante car Kyber est un KEM, pas un système de chiffrement direct
        key = shared_secret[:32]  # Utiliser 32 octets pour AES-256
        iv = os.urandom(16)
        
        # Chiffrer avec AES
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        message_ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Concaténer l'IV, le ciphertext Kyber et le message chiffré AES
        # Format: [Kyber ciphertext length (4 bytes)][Kyber ciphertext][IV][AES encrypted message]
        kyber_len = len(ciphertext).to_bytes(4, byteorder='big')
        encrypted = kyber_len + ciphertext + iv + message_ciphertext
        
        return encrypted, {
            "clé publqiue": public_key,
            "clé sécrète": private_key,
            # "shared_secret": shared_secret
        }
    
    # def encrypt_dilithium(self, message, dilithium_variant):
    #     if not PQ_AVAILABLE:
    #         raise ImportError("Module pqcrypto non installé!")
        
    #     # Choisir la variante de Dilithium
    #     if dilithium_variant == "DILITHIUM2":
    #         variant = Dilithium2
    #     elif dilithium_variant == "DILITHIUM3":
    #         variant = Dilithium3
    #     elif dilithium_variant == "DILITHIUM5":
    #         variant = Dilithium5
        
    #     # Générer les clés
    #     public_key, private_key = dilithium_generate_keypair(variant)
        
    #     # Dilithium est un schéma de signature, pas de chiffrement
    #     # On va donc signer le message, puis le chiffrer avec AES pour montrer les deux aspects
    #     signature = dilithium_sign(message.encode(), private_key, variant)
        
    #     # Chiffrer le message avec AES pour démontrer la confidentialité
    #     key = os.urandom(32)
    #     iv = os.urandom(16)
        
    #     padder = padding.PKCS7(128).padder()
    #     padded_data = padder.update(message.encode()) + padder.finalize()
        
    #     cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    #     encryptor = cipher.encryptor()
    #     ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
    #     # Format: [Signature length (4 bytes)][Signature][IV][AES encrypted message]
    #     sig_len = len(signature).to_bytes(4, byteorder='big')
    #     encrypted = sig_len + signature + iv + ciphertext
        
    #     return encrypted, {
    #         "public_key": public_key,
    #         "private_key": private_key,
    #         "aes_key": key,
    #         "signature": signature
    #     }
        
    def print_card(self, encrypted_message_hexa):
        top_line = ' '.join(list(HEXA_CHARS))
        res = '   ' + top_line
        res += '\n'
        
        for c in encrypted_message_hexa:
            line = c + '  '
            for c_line in top_line:
                if c == c_line:
                    line += '▮'.upper()
                else:
                    line += ' '
            res += line
            res += '\n'
        return res    
    
    def format_output(self, data, output_format):
        if output_format == "base64":
            return base64.b64encode(data).decode('utf-8')
        elif output_format == "hex":
            return data.hex()
        elif output_format == "base10":
            # Convertir en base 10 (représentation décimale des octets)
            return ' '.join([str(b) for b in data])
        elif output_format == "carte perforée":
            return self.print_card(data.hex()) 
        
    def format_keys(self, keys, output_format):
        formatted_keys = {}
        
        for key_name, key_value in keys.items():
            if isinstance(key_value, bytes):
                if output_format == "carte perforée":
                    output_format = "hex"
                formatted_keys[key_name] = self.format_output(key_value, output_format)
            else:
                # Pour les clés PEM, on garde le format
                formatted_keys[key_name] = key_value.decode('utf-8')
                
        return formatted_keys

    def encrypt(self, message, algorithm, key_size, output_format):
        if algorithm == "AES":
            encrypted, keys = self.encrypt_aes(message, key_size)
        elif algorithm == "RSA":
            encrypted, keys = self.encrypt_rsa(message, key_size)
        elif algorithm == "ECC":
            encrypted, keys = self.encrypt_ecc(message, key_size)
        elif algorithm == "KYBER" and PQ_AVAILABLE:
            encrypted, keys = self.encrypt_kyber(message, key_size)
        else:
            raise ValueError(f"Algorithme non supporté: {algorithm}")
        # elif algorithm == "DILITHIUM" and PQ_AVAILABLE:
        #     encrypted, keys = self.encrypt_dilithium(message, key_size)
        
        # Formater le résultat chiffré selon le format demandé
        formatted_output = self.format_output(encrypted, output_format)
        
        # Formater les clés selon le format demandé
        formatted_keys = self.format_keys(keys, output_format)
        
        return formatted_output, formatted_keys
        

    def display_results(self, message, encrypted_message, keys, algorithm, key_size, output_format):
        self.print_header()
        print(f"Algorithme utilisé: {algorithm}")
        print(f"Taille de clé: {key_size}")
        print(f"Format d'encodage: {output_format}")
        print(f"Message: {message}")
        # print("\n" + "=" * WIDTH)
        
        # if len(keys) == 2:
        #     print("\nCLÉS GÉNÉRÉES:")
        # elif len(keys) == 1:
        #     print("\nCLÉ GÉNÉRÉE:")
        # print("-" * 60)
        
        for key_name, key_value in keys.items():
            print(f"\n{key_name.upper()}:")
            print("-" * 40)
            print(key_value)
        
        # print("\n" + "=" * WIDTH)
        print("\nMESSAGE CHIFFRÉ:")
        print("-" * WIDTH)
        print(encrypted_message)
        # print("\n" + "=" * WIDTH)
        
        input("\nAppuyez sur Entrée pour continuer...")

    def run(self):
        while True:
            # Obtenir les entrées utilisateur
            message, algorithm, key_size, output_format = self.get_user_input()
            if message == ":q:":
                self.print_header()
                print("Merci d'avoir utilisé l'application de chiffrement!")
                break
            
            # Chiffrer le message
            encrypted_message, keys = self.encrypt(message, algorithm, key_size, output_format)
            
            # Afficher les résultats
            self.display_results(message, encrypted_message, keys, algorithm, key_size, output_format)
            
            # Demander si l'utilisateur veut continuer
            self.print_header()
            # choice = input("Voulez-vous chiffrer un autre message ? (o/n): ")
            # if choice.lower() != 'o':
            #     self.print_header()
            #     print("Merci d'avoir utilisé l'application de chiffrement!")
            #     break

if __name__ == "__main__":
    app = EncryptionApp()
    app.run()