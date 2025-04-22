from config import  *
from logos import *
from crypto import *
from logs import write_counters, read_counters, write_log

import roman
import os
import base64
import textwrap
from datetime import datetime
import uuid
from time import sleep

from escpos.printer import LP

PRINTER = LP(printer_name=PRINTER_NAME, autoflush=True)
N_USE, N_PRINT = read_counters(COUNTER_FILE)

# --- Constants ---
ACTIONS_CHOICES = {
    '1': 'Chiffrer ou dechiffrer un message (Cesar, Vigenere, Enigma)',
    '2': 'Chiffrer un message (AES, RSA, ECC, El-Gamal)',
    '3': 'Hacher un message',
    '4': 'Quitter'
}

ALGORITHMS = {
    'classical': {'1': 'Cesar', '2': 'Vigenere', '3': 'Enigma'},
    'modern': {'1': 'AES', '2': 'RSA', '3': 'ECC', '4': 'El-Gamal'},
    'hash': {'1': 'SHA-2 256', '2': 'SHA-2 384', '3': 'SHA-2 512',
             '4': 'SHA-3 256', '5': 'SHA-3 384', '6': 'SHA-3 512'}
}

KEYS_SIZES = {
    'AES': {'1': 128, '2': 192, '3': 256},
    'RSA': {'1': 1024, '2': 2048, '3': 3072, '4': 4096},
    'ECC': {'1': "SECP 256 R1", '2': "SECP 384 R1", '3': "SECP 521 R1"},
    'El-Gamal': {'1': 1024, '2': 2048, '3': 3072, '4': 4096}
}

OUTPUT_FORMAT = {
    '1': 'Binaire',
    '2': 'Nombre',
    '3': 'Hexadecimal',
    '4': 'Base 64'
}

def get_base64_uuid():
    uid = uuid.uuid4().bytes
    # Add padding if removed
    return base64.urlsafe_b64encode(uid).rstrip(b'=').decode('ascii')

def display_menu(title, options):
    """Affiche un menu numerote a partir d'un dictionnaire."""
    print(f"\n--- {title} ---")
    for key, value in options.items():
        print(f"{key}. {value}")
    print("-" * (len(title) + 6))

def get_choice(prompt, valid_choices):
    """Demande a l'utilisateur de faire un choix valide."""
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        else:
            print(f"Choix invalide. Veuillez entrer un numero parmi : {', '.join(valid_choices)}")

def get_message(action="entrer"):
    """Demande a l'utilisateur d'entrer un message."""
    print(f"\nVeuillez entrer le message a {action} :")
    message = input("> ")
    return message


def format_output(data_bytes, format_choice_key):
    """Met en forme les donnees binaires selon le choix de l'utilisateur."""
    format_name = OUTPUT_FORMAT.get(format_choice_key, 'Hexadecimal') # Defaut Hex
    # print(f"\n--- Resultat (Format: {format_name}) ---")
    try:
        if format_name == 'Hexadecimal':
            return data_bytes.hex()
        elif format_name == 'Base 64':
            return base64.b64encode(data_bytes).decode('utf-8')
        elif format_name == 'Binaire':
            return ' '.join(format(byte, '08b') for byte in data_bytes)
        elif format_name == 'Nombre':
            # Attention: tres grand pour les hashs/chiffrements longs
            n = int.from_bytes(data_bytes, 'big')
            return f"{n:,}".replace(',', ' ')
        else:
            return data_bytes.hex() # Fallback
    except Exception as e:
        return f"Erreur lors du formatage : {e}"

def handle_classical():
    
    display_menu("Choisissez un algorithme classique", ALGORITHMS['classical'])
    algo_choice_key = get_choice("Votre choix : ", ALGORITHMS['classical'].keys())
    algo_name = ALGORITHMS['classical'][algo_choice_key]

    # print(f"\nAlgorithme choisi : {algo_name}")
    
    display_menu("Action", {'1': 'Chiffrer', '2': 'Dechiffrer'})
    action_choice = get_choice("Votre choix : ", ['1', '2'])
    decrypt = (action_choice == '2')
    action_text = "dechiffrer" if decrypt else "chiffrer"
    
    def display_res(ciphertext, message, key, algo, decrypt):
        global N_USE
        N_USE += 1
        clear_screen()
        print(LOGO_HEADER_SCREEN)
        print('\n')
        print(f'Algorithme : {algo}')
        if algo == 'Cesar':
            print(f'Cle : a={key}')
            write_log(f'{algo}, {key}, {message},')
        elif algo == 'Vigenere':
            print(f'Cle : {key}')
            write_log(f'{algo}, {key}, {message},')
        elif algo == 'Enigma':
            key_pass = key['key']
            infos = key['infos']
            reflector = infos['reflector']
            rotors = [roman.toRoman(x) for x in infos['rotors']]
            rotors = ' '.join(rotors)
            print(f'Configuration :')
            print(f'  Refecteur: {reflector}')
            print(f'  Rotors: {rotors}')
            print(f'Cle : {key_pass}')
            write_log(f'{algo}, [{rotors},{reflector}], {message},')
        if decrypt:
            print(f'Mesage chiffre : {message}')
            print('\nMESSAGE DECHIFFRE')
            print('-'*17)
        else:
            print(f'Message : {message}')
            print('\nMESSAGE CHIFFRE')
            print('-'*15)
        print(ciphertext)
        
    if algo_name == 'Cesar':
        while True:
            try:
                # Note: Une cle de Cesar est un decalage numerique.
                key = input("Entrez la cle a=")
                if 'a' <= key <= 'z':
                    break
            except ValueError:
                print("Cle invalide.")
        message = get_message(action_text)
        res = caesar_cipher(message, ord(key) - ord('a'), decrypt)
    elif algo_name == 'Vigenere':
        while True:
            # Note: Une cle Vigenere est un mot ou une phrase.
            key = input("Entrez la cle (mot/phrase, ex: 'crypto') : ").strip()
            if key and key.isalpha(): # Simple validation: que des lettres
                break
            else:
                print("Cle invalide. Veuillez entrer un mot compose uniquement de lettres.")
        message = get_message(action_text)
        res = vigenere_cipher(message, key, decrypt)
    elif algo_name == 'Enigma':
        while True:
            # Note: Une cle Vigenere est un mot ou une phrase.
            key = input("Entrez la cle compose de 3 lettres (ex. ERT) : ").strip()
            if key and key.isalpha() and len(key) == 3: # Simple validation: que des lettres
                break
            else:
                print("Cle invalide. Veuillez entrer un mot compose uniquement de lettres.")
        key = key.upper()
        message = get_message(action_text)
        infos, res = enigma_cipher(message, key)
        key = {'key': key, 'infos': infos}
        
        display_res(res, message, key, algo_name, decrypt)
        
        input('\n\nAppuyer sur entree pour continuer ...')
        clear_screen()
        
    
def handle_modern():
    display_menu("Choisissez un algorithme", ALGORITHMS['modern'])
    algo_choice_key = get_choice("Votre choix : ", ALGORITHMS['modern'].keys())
    algo_name = ALGORITHMS['modern'][algo_choice_key]
    
    key_param = None
    if algo_name in KEYS_SIZES:
        display_menu(f"Choisissez la taille/type de cle pour {algo_name}", KEYS_SIZES[algo_name])
        key_choice = get_choice("Votre choix : ", KEYS_SIZES[algo_name].keys())
        key_param = KEYS_SIZES[algo_name][key_choice]
        # print(f"Parametre de cle choisi : {key_param}")
    else:
        # Certains algos pourraient ne pas avoir de taille de cle selectionnable ici
        print(f"(!) Pas de selection de taille de cle pour {algo_name} dans cette demo.")
        # On pourrait definir une taille par defaut ou demander autrement
        
    message = get_message("chiffrer")
    
    def display_res(message, res, algo, key_param, keys, output_format):
        global N_USE
        N_USE += 1
        clear_screen()
        print(LOGO_HEADER_SCREEN)
        print('\n')
        print(f'Algorithme : {algo}')
        print(f'Taille de la cle : {key_param}')
        output_format = OUTPUT_FORMAT[str(output_format)]
        print(f"Format d'encodage: {output_format}")
        print(f"Message: {textwrap.fill(message, width=MINITEL_SCREEN_WHIDTH)}")
        write_log(f'{algo}, {key_param}, {message}, {output_format}')
        if keys is not None:
            for key_name, key_value in keys.items():
                print(f"\n{key_name.upper()}:")
                if isinstance(key_value, dict):
                    for k, v in key_value.items():
                        text_formated = format_output(v, output_format)
                        print(f'{k}:')
                        print(textwrap.fill(text_formated, width=80))
                else:
                    text_formated = format_output(key_value, output_format)
                    print(textwrap.fill(text_formated, width=80))
        
        print("\n\nMESSAGE CHIFFRE:")
        if isinstance(res, dict):
            for k, v in res.items():
                text_formated = format_output(v, output_format)
                print(f'{k}:')
                print(textwrap.fill(text_formated, width=80))
        else:
            text_formated = format_output(res, output_format)
            print(textwrap.fill(text_formated, width=80))
        print('\n')
    
    res = None
    if algo_name == 'AES':
        res, keys = encrypt_aes(message, key_param)
        
    elif algo_name == 'RSA':
        res, _, keys = encrypt_rsa(message, key_param)
        
    elif algo_name == 'ECC':
        res, keys, _ = encrypt_ecc(message, key_param)
    elif algo_name == 'El-Gamal':
        res, _, keys = encrypt_elgamal(message, key_param)
    
    display_menu("Choisissez un format de sortie du hash", OUTPUT_FORMAT)
    format_choice = get_choice("Votre choix : ", OUTPUT_FORMAT.keys())
    
    display_res(message, res, algo_name, key_param, keys, format_choice)
    while True:
        choice = input('Imprimer le resultat ? (o/n) ')
        if choice == "o":
            print_ticket(algo_name, message, res, key_param, keys, format_choice)
            input('Appuyer sur entree pour continuer ...')
            return
        elif choice == "n":
            return
        else:
            print("Choix invalide choisir o pour oui et n pour non.")

def handle_hash():
    display_menu("Choisissez un algorithme de hachage", ALGORITHMS['hash'])
    algo_choice_key = get_choice("Votre choix : ", ALGORITHMS['hash'].keys())
    algo_name = ALGORITHMS['hash'][algo_choice_key]

    # print(f"\nAlgorithme choisi : {algo_name}")

    message = get_message("hacher")
    result_bytes = compute_hashes(message, algo_name)
    
    if result_bytes is not None:
        formatted_result = format_output(result_bytes, 3)
        global N_USE
        N_USE += 1
        clear_screen()
        print(LOGO_HEADER_SCREEN)
        print('\n')
        print(f'Algorithme : {algo_name}')
        print(f'Message : {message}\n')
        print('-'*MINITEL_SCREEN_WHIDTH)
        print('\nMESSAGE HACHE')
        print(formatted_result)
        print('\n')
        write_log(f'{algo_name}, , {message}, ')
        while True:
            choice = input('Imprimer le resultat ? (o/n) ')
            if choice == "o":
                print_ticket(algo_name, message, formatted_result)
                input('Appuyer sur entree pour continuer ...')
                return
            elif choice == "n":
                return
            else:
                print("Choix invalide choisir o pour oui et n pour non.")
        
def print_ticket(algo, message, ciphertext, keys_param = None, keys = None, format = None, decrypt = None):
    global N_PRINT
    N_PRINT += 1
    current_datetime = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    PRINTER.set(align='left', font='a', width=1, height=1)
    PRINTER.text('\n')
    PRINTER.text('\n')
    PRINTER.text('\n')
    sleep(.5)
    PRINTER.text(LOGO_HEADER_PRINTER)
    PRINTER.text('\n\n')
    PRINTER.text(f'Algorithme : {algo}\n')
    if keys_param is not None:
        PRINTER.text(f'Taille de la cle : {keys_param}\n')
    if format is not None:
        PRINTER.text(f'Format : {OUTPUT_FORMAT[str(format)]}\n')
    PRINTER.text(f'Message : {message}\n')
    if keys is not None:
        for key_name, key_value in keys.items():
            PRINTER.text(f"\n\n{key_name.upper()}\n")
            if isinstance(key_value, dict):
                for k, v in key_value.items():
                    text_formated = format_output(v, format)
                    PRINTER.text(f'{k}\n')
                    PRINTER.text(text_formated.replace(' ', '')+'\n')
            else:
                text_formated = format_output(key_value, format)
                PRINTER.text(text_formated.replace(' ', '')+'\n')
    if keys_param is None:
        PRINTER.text('\n\nMESSAGE HACHE\n')
    else:
        PRINTER.text('\n\nMESSAGE CHIFFRE\n')
    if isinstance(ciphertext, dict):
        for k, v in ciphertext.items():
            text_formated = format_output(v, format)
            PRINTER.text(f'{k}:\n')
            PRINTER.text(textwrap.fill(text_formated.replace(' ', ''), width=48)+'\n\n')
    else:
        if format is not None:
            text_formated = format_output(ciphertext, format)
            PRINTER.text(textwrap.fill(text_formated.replace(' ', ''), width=48)+'\n\n')
        else:
            PRINTER.text(textwrap.fill(ciphertext.replace(' ', ''), width=48) + '\n\n')
    PRINTER.text('-'*48+'\n')
    PRINTER.text('\n'+current_datetime)
    PRINTER.cut()
    PRINTER.flush()

def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

def run():
    while True:
        clear_screen()
        print(LOGO_HEADER_SCREEN)
        display_menu("Que voulez-vous faire ?", ACTIONS_CHOICES)
        action_choice_key = get_choice("Votre choix : ", ACTIONS_CHOICES.keys())

        if action_choice_key == '1': # Cryptographie classique
            handle_classical()
        elif action_choice_key == '2': # Cryptographie moderne
            handle_modern()
        elif action_choice_key == '3': # Hachage
            handle_hash()
        elif action_choice_key == '4': # Quitter
            write_counters(COUNTER_FILE, N_USE, N_PRINT)
            clear_screen()
            print(LOGO_HEADER_SCREEN)
            print("             Merci d'avoir utilise l'application de chiffrement!")
            break
            
        else:
            # Ne devrait pas arriver grâce a get_choice, mais par securite
            print("Choix d'action principal invalide.")

if __name__ == "__main__":
    run()