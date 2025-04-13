import os
import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asymm_padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
import hashlib
    
WIDTH = 80
HEXA_CHARS = '0123456789abcdef'

AES_BLOCK_SIZE = 128  # bits
AES_IV_SIZE = 16      # bytes

def encrypt_aes(message: str, key_size: int = 256, key: bytes = None) -> tuple[bytes, bytes]:
    """
    Encrypt a message using AES in CBC mode with PKCS7 padding.

    Args:
        message (str): The plaintext message to encrypt.
        key_size (int): The size of the AES key in bits (128, 192, or 256). Default is 256.
        key (bytes, optional): The AES key. If None, a random key is generated.

    Returns:
        tuple[bytes, bytes]: (iv + ciphertext, key used)
    """
    if key is None:
        key = os.urandom(key_size // 8)

    iv = os.urandom(AES_IV_SIZE)

    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext, {'cle secrete': key}

def encrypt_rsa(message: str, key_size: int = 2048) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt a message using RSA with OAEP padding.

    Args:
        message (str): The plaintext message to encrypt.
        key_size (int): RSA key size in bits (e.g., 2048 or 4096). Default is 2048.

    Returns:
        tuple[bytes, bytes, bytes]: (encrypted message, private_key_pem, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    encrypted = public_key.encrypt(
        message.encode(),
        asymm_padding.OAEP(
            mgf=asymm_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    
    priv_numbers = private_key.private_numbers()
    pub_numbers = public_key.public_numbers()
    
    private_components = {
        "n": int_to_bytes(priv_numbers.public_numbers.n),
        "e": int_to_bytes(priv_numbers.public_numbers.e),
        "d": int_to_bytes(priv_numbers.d),
        "p": int_to_bytes(priv_numbers.p),
        "q": int_to_bytes(priv_numbers.q),
    }

    public_components = {
        "n": int_to_bytes(pub_numbers.n),
        "e": int_to_bytes(pub_numbers.e),
    }
    
    keys_pem = {
        'cle secrete': private_key_pem,
        'cle publqiue': public_key_pem
        }
    keys_elements = {
        'elements cle secrete': private_components,
        'elements cle publique': public_components
        }

    return encrypted, keys_pem, keys_elements

def compute_hashes(message: str, algorithm) -> dict:
    """
    Compute multiple hashes for a given message in raw binary format.

    Args:
        message (str): The message to hash.

    Returns:
        dict: {hash_name: bytes}
    """
    if algorithm == 'SHA2-256':
        hash = hashlib.sha256(message.encode()).digest()
    elif algorithm == 'SHA2-384':
        hash = hashlib.sha384(message.encode()).digest()
    elif algorithm == 'SHA2-512':
        hash = hashlib.sha512(message.encode()).digest()
    elif algorithm == 'SHA3-256':
        hash = hashlib.sha3_256(message.encode()).digest()
    elif algorithm == 'SHA3-384':
        hash = hashlib.sha3_384(message.encode()).digest()
    elif algorithm == 'SHA3-512':
        hash = hashlib.sha3_512(message.encode()).digest()
    return hash

def print_card(hexa_str):
    """
    Generates a formatted string representing a card with hexadecimal characters.

    Args:
        hexa_str (str): A string containing hexadecimal characters to display on the card.

    Returns:
        str: A formatted string where each line represents a row of the card.
             The first line contains all possible hexadecimal characters as headers.
             Subsequent lines show matching patterns based on the input hexa_str.

    Note:
        This function relies on the global HEXA_CHARS variable which should be imported or defined elsewhere.
    """
    # Create the top line with all hexadecimal characters separated by spaces
    top_line = ' '.join(list(HEXA_CHARS))
    res = '   ' + top_line  # Add leading spaces and the top line to the result string
    res += '\n'  # Add a newline after the top header
    
    for c in hexa_str:
        """
        For each character in hexa_str, create a new row starting with the character
        followed by two spaces. Then, compare this character with each character in
        the top_line to determine if there's a match (represented by '█') or not
        (represented by a space).
        """
        line = c + '  '  # Start the line with current character and two spaces
        for c_line in top_line:
            if c == c_line:
                line += '█'  # Add block character if there's a match
            else:
                line += ' '  # Add space if no match
        res += line + '\n'  # Add the completed line to result and a newline

    return res


def int_to_bytes(n: int) -> bytes:
    """
    Converts an integer to its corresponding byte representation.

    Args:
        n (int): The integer value to be converted to bytes.

    Returns:
        bytes: The byte representation of the integer in big-endian format.

    Note:
        If n is zero, returns a single byte containing zero (0x00).
    """
    # Convert integer to bytes using big-endian format
    # Calculate the number of bytes needed by taking the bit length of n and rounding up
    return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

class App:
    def __init__(self):
        self.algorithms = {
                'Chiffrer un message.': ["AES", "RSA"],
                'Signer un message.': ["ECC"],
                'Hacher un message.': ['SHA2-256', 'SHA2-384', 'SHA2-512',
                    'SHA3-256', 'SHA3-384', 'SHA3-512']
            }
        self.key_sizes = {
            "AES": [128, 192, 256],
            "RSA": [1024, 2048, 3072, 4096],
            "ECC": ["SECP256R1", "SECP384R1", "SECP521R1"],
        }
        
        self.output_formats = ["base64", "hex", "base10", "carte perforee"]
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_header(self):
        self.clear_screen()
        logo = '''
______| |_____________________________________________________________| |_______
______   _____________________________________________________________   _______
      | |                                                             | |  
      | |                 ██████╗  ██████╗ ██╗███████╗                | |  
      | |                 ╚════██╗██╔════╝███║██╔════╝                | |  
      | |                  █████╔╝███████╗╚██║███████╗                | |  
      | |                  ╚═══██╗██╔═══██╗██║╚════██║                | |  
      | |                 ██████╔╝╚██████╔╝██║███████║                | |  
      | |                 ╚═════╝  ╚═════╝ ╚═╝╚══════╝                | |  
      | |                                                             | |  
      | |      ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗      | |  
      | |     ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗     | |  
      | |     ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║     | |  
      | |     ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║     | |  
      | |     ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝     | |  
      | |      ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝      | |  
______| |_____________________________________________________________| |_______
______   _____________________________________________________________   _______
      | |                                                             | |  
        '''
        print(logo)
        # print(" - entrer :q: pour quitter")
        # print("=" * WIDTH)
        # print()
        
    def get_user_choice(self, message, choices):
        """Get user's choice from a list of options.
    
        Args:
            message (str): The prompt message to display.
            choices (list): List of available choices as strings.
        
        Returns:
            int: The index (1-based) of the selected choice.
        """
        print(message)
        for i, action in enumerate(choices, 1):
            print(f"({i}) - {action}")
    
        while True:
            try:
                n = len(choices)
                choice = int(input(f"Choix (1-{n}): "))
                if 1 <= choice <= n:
                    return choice-1
                else:
                    print(f"Choix invalide. Veuillez choisir entre 1 et {n}.")
            except ValueError:
                print("Veuillez entrer un nombre.")
                
    def format_output(self, data, output_format):
        if output_format == "base64":
            return base64.b64encode(data).decode('utf-8')
        elif output_format == "hex":
            return data.hex()
        elif output_format == "base10":
            # Convertir en base 10 (représentation décimale des octets)
            return ''.join([str(b) for b in data])
        elif output_format == "carte perforee":
            return print_card(data.hex())
    
    def format_keys(self, keys, output_format):
        formatted_keys = {}
        
        for key_name, key_value in keys.items():
            if isinstance(key_value, bytes):
                if output_format == "carte perforee":
                    output_format = "hex"
                formatted_keys[key_name] = self.format_output(key_value, output_format)
            else:
                # Pour les clés PEM, on garde le format
                formatted_keys[key_name] = key_value.decode('utf-8') 
        return formatted_keys
    
    def display_results(self, message, encrypted_message, keys, algorithm, key_size, output_format):
        self.print_header()
        print(f"Algorithme utilisé: {algorithm}")
        if key_size is not None:
            print(f"Taille de clé: {key_size}")
        print(f"Format d'encodage: {output_format}")
        print(f"Message: {message}")
        
        if keys is not None:
            for key_name, key_value in keys.items():
                print(f"\n{key_name.upper()}:")
                print('-'*WIDTH)
                if isinstance(key_value, str):
                    print(key_value)
                elif isinstance(key_value, dict):
                    for k, v in key_value.items():
                        print(f'{k}:')
                        print(v)
                        
        if any(x in algorithm for x in self.algorithms['Hacher un message.']):
            print("\nMESSAGE HASHE:")
        
        if any(x in algorithm for x in self.algorithms['Chiffrer un message.']):
            print("\nMESSAGE CHIFFRE:")
            
        print('-'*WIDTH)
        print(encrypted_message)
        
    def run(self):
        while True:
            self.print_header()

            self.action_choices = [
                    'Chiffrer un message.',
                    'Signer un message.',
                    'Hacher un message.',
                    'Quitter.'
                ]
            
            self.output_formats = ["base64", "hex", "base10", "carte perforee"]
            
            action = self.get_user_choice(
                message = 'Que voulez-vous faire?',
                choices = self.action_choices
            )
            action_string = self.action_choices[action]
            
            if action == 0: # Chiffrer
                algorithm = self.get_user_choice(
                        message = 'Choisissez un algorithme.',
                        choices = self.algorithms[action_string]
                    )
                algorithm_string = self.algorithms[action_string][algorithm]
                key_size = self.get_user_choice(
                        message = 'Choisissez la taille de la clé.',
                        choices = self.key_sizes[algorithm_string]
                )
                key_size_string = self.key_sizes[algorithm_string][key_size]
                print(f'Chiffrer un message: {algorithm_string} {key_size_string}')
                
                message = input("Entrez le message à chiffrer: ")
                
                output_format = self.get_user_choice(
                    message = 'Choisissez le format d\'affichage.',
                    choices=self.output_formats
                )
                
                if algorithm_string == 'AES':
                    ciphertext, keys = encrypt_aes(message, key_size_string)
                    formatted_output = self.format_output(ciphertext, self.output_formats[output_format])
                    formatted_keys = self.format_keys(keys, self.output_formats[output_format])
                    self.display_results(message, formatted_output, formatted_keys, algorithm_string,
                                     key_size_string, self.output_formats[output_format])
                elif algorithm_string == 'RSA':
                    ciphertext, _, keys_elements = encrypt_rsa(message, key_size_string)
                    formatted_output = self.format_output(ciphertext, self.output_formats[output_format])
                    formatted_keys_private = self.format_keys(keys_elements['elements cle secrete'], self.output_formats[output_format])
                    formatted_keys_public = self.format_keys(keys_elements['elements cle publique'], self.output_formats[output_format])
                    self.display_results(message, formatted_output,
                                         {'cle secrete': formatted_keys_private, 'cle publique': formatted_keys_public}, 
                                         algorithm_string, key_size_string, self.output_formats[output_format])
                    
            elif action == 1: # Signer
                algorithm = self.get_user_choice(
                        message = 'Choisissez un algorithme.',
                        choices = self.algorithms[action_string]
                    )
                algorithm_string = self.algorithms[action_string][algorithm]
                key_size = self.get_user_choice(
                        message = 'Choisissez la taille de la clé.',
                        choices = self.key_sizes[algorithm_string]
                )
                key_size_string = self.key_sizes[algorithm_string][key_size]
                print(f'Signer un message: {algorithm_string} {key_size_string}')
            elif action == 2: # Hacher
                algorithm = self.get_user_choice(
                        message = 'Choisissez un algorithme.',
                        choices = self.algorithms[action_string]
                    )
                algorithm_string = self.algorithms[action_string][algorithm]
                message = input("Entrez le message à hacher: ")
                
                output_format = self.get_user_choice(
                    message = 'Choisissez le format d\'affichage.',
                    choices=self.output_formats
                )
                hash = compute_hashes(message, algorithm_string)
                formatted_output = self.format_output(hash, self.output_formats[output_format])
                self.display_results(message, formatted_output, None, algorithm_string, None, self.output_formats[output_format])
                
            elif action == 3:
                self.print_header()
                print("             Merci d'avoir utilisé l'application de chiffrement!")
                print('\n')
                break
            return
        
if __name__ == "__main__":
    app = App()
    app.run()
