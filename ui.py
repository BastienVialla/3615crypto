from __future__ import annotations
import os
import sys
import time
import unicodedata
from typing import List, Set
import textwrap
import base64

from logos import *
from config import MINITEL_SCREEN_WHIDTH


def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.01):
  """Prints text character by character with a delay.

  Args:
    text: The string to print.
    delay: The time delay (in seconds) between each character.
  """
  for char in text:
    sys.stdout.write(char)
    sys.stdout.flush()
    time.sleep(delay)
  print()
        
def new_screen():
    clear_screen()
    # print(LOGO_HEADER_SCREEN)
    cout = '1 Fr par minute' 
    # print(' '*(MINITEL_SCREEN_WHIDTH-len(cout))+f'{cout}')
    slow_print(get_logo_header_screen(cout))
    
def normalize_string(string):
  """
  Normalize a string by removing accents
  """
  normalized_string = unicodedata.normalize('NFD', string)

  normalized_string = ''.join([
      car for car in normalized_string
      if unicodedata.category(car) != 'Mn'
  ])

  return normalized_string

def get_message():
    new_screen()
    while True:
        print(normalize_string(f"\nVeuillez entrer le message :"))
        message = input('> ')
        if len(message) > 0:
            return message
        else:
            print(normalize_string("Le message ne peut-être vide."))

def display_menu(title: str, options: dict):
    """
    Affiche un menu numéroté à partir d'un dictionnaire.

    Args:
        title (str): Le titre à afficher au-dessus du menu.
        options (dict): Un dictionnaire où les clés sont les numéros
                        d'option (str) et les valeurs sont les descriptions (str).
                        Ex: {'1': 'Option A', '2': 'Option B'}
    """
    new_screen()
    normalized_title = normalize_string(title)
    print(f"\n--- {normalized_title} ---\n")
    if not options:
        print("Aucune option disponible.")
    else:
        # Détermine la largeur nécessaire pour les numéros d'option
        # max_key_width = max(len(key) for key in options.keys()) if options else 0
        for key, value in options.items():
            if isinstance(value, dict):
                if value.get('show', True) == False:
                    continue
                title = value['option']
                description = value.get('description', '')
                prefix = f'{key}. {title}'
                if len(description) > 0:
                    prefix += ' | '
                line = prefix+description
                line = normalize_string(line)
                if len(line) > MINITEL_SCREEN_WHIDTH:
                    slow_print(textwrap.fill(line, MINITEL_SCREEN_WHIDTH,subsequent_indent=" "*len(prefix)))
                    # look for previous space to cut the line
                    # for i in range(MINITEL_SCREEN_WHIDTH, 0, -1):
                    #     if line[i] == " ":
                    #         print(line[:i])
                    #         print(' '*(len(prefix)-1)+line[i:])
                    #         break
                else:
                    slow_print(line)
            else:
                slow_print(f"{key}. {value}") # Version la plus simple
                
    # print("\n"+"-" * MINITEL_SCREEN_WHIDTH) # Ligne de séparation simple

def get_choice(prompt: str, valid_choices: List[str] | Set[str], to_hide: None | List[str] | Set[str] = None) -> str:
    """
    
    """
    # Convertir en set pour une recherche efficace, si ce n'est pas déjà le cas
    valid_set = set(valid_choices)
    if not valid_set:
         # Gérer le cas où aucune option n'est valide (ne devrait pas arriver si le menu est bien construit)
         print(normalize_string("Erreur : Aucune option valide fournie à get_choice."))
         return "" # Ou lever une exception

    while True:
        choice = input(prompt).strip()
        if choice in valid_set:
            return choice
        else:
            # Construit un message d'erreur plus lisible
            valid_options_str = ", ".join(sorted(list(valid_set)))
            for x in to_hide:
                valid_options_str = valid_options_str.replace(x, '')
            valid_options_str = textwrap.fill(valid_options_str, MINITEL_SCREEN_WHIDTH)
            print(normalize_string(f"Choix invalide. Veuillez entrer un numero parmi : {valid_options_str}"))

def get_options(options: list):
    show = list()
    for x in options:
        if x['show']:
            show.append(x)
    res = {}
    i = 1
    for x in show:
        if x['show']:
            res[str(i)] = x
            i += 1
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

def format_output(data_bytes, format_name):
    """Met en forme les donnees binaires selon le choix de l'utilisateur."""
    
    # print(f"\n--- Resultat (Format: {format_name}) ---")
    try:
        if format_name == 'Hexadécimal (base 16)':
            return data_bytes.hex()
        elif format_name == 'Base 64':
            return base64.b64encode(data_bytes).decode('utf-8')
        elif format_name == 'Binaire (base 2)':
            return ' '.join(format(byte, '08b') for byte in data_bytes)
        elif format_name == 'Nombre (base 10)':
            # Attention: tres grand pour les hashs/chiffrements longs
            n = int.from_bytes(data_bytes, 'big')
            return f"{n:,}".replace(',', ' ')
        else:
            return data_bytes.hex() # Fallback
    except Exception as e:
        return f"Erreur lors du formatage : {e}"

def display_res(infos, res, keys = None):
    new_screen()
    print('\n')
    print(normalize_string(infos))
    print('-'*MINITEL_SCREEN_WHIDTH)
    print('\n')
    if keys is not None:
        print(normalize_string(keys))    
    print(normalize_string(res))
    while True:
        choice = input('Imprimer le resultat ? (o/n) ')
        if choice == "o" or choice == "n":
            return choice
        else:
            print("Choix invalide choisir o pour oui et n pour non.")
    