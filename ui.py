from __future__ import annotations
import os
import sys
import time
import unicodedata
from typing import List, Set, Any, Optional, Dict, Union
import textwrap
import base64

from logos import *
from config import MINITEL_SCREEN_WHIDTH


# --- Constants ---
DEFAULT_SLOW_PRINT_DELAY: float = 0.008
COST_PER_MINUTE_INFO: str = "1 Fr par minute"
INVALID_CHOICE_PROMPT: str = "Choix invalide."
PLEASE_ENTER_PROMPT: str = "Veuillez entrer un numero parmi : "
EMPTY_MESSAGE_ERROR: str = "Le message ne peut-être vide."
PROMPT_INDICATOR: str = "> "
PRINT_RESULT_PROMPT: str = "Imprimer le resultat ? (o/n) "
INVALID_PRINT_CHOICE: str = "Choix invalide choisir o pour oui et n pour non."
SPEED_UPDATED_MSG: str = "Vitesse d'affichage mise à jour."

# Constants for output formats
FORMAT_HEX = 'Hexadécimal (base 16)'
FORMAT_B64 = 'Base 64'
FORMAT_BIN = 'Binaire (base 2)'
FORMAT_DEC = 'Nombre (base 10)'
FORMAT_FALLBACK = FORMAT_HEX

# Speed constants
SPEED_SLOW = 0.008   # Minitel 1
SPEED_MEDIUM = 0.002 # Minitel 1B+
SPEED_FAST = 0.001   # Minitel 2+
SPEED_INSTANT = 0.0  # Temps réel

SUPPORTED_FORMATS = {
    FORMAT_HEX: lambda b: b.hex(),
    FORMAT_B64: lambda b: base64.b64encode(b).decode('utf-8'),
    FORMAT_BIN: lambda b: ' '.join(format(byte, '08b') for byte in b),
    FORMAT_DEC: lambda b: f"{int.from_bytes(b, 'big'):,}".replace(',', ' '),
}

# Define a type alias for menu option structure for clarity
MenuOptionDetail = Dict[str, Union[str, bool]] # e.g., {'option': 'Text', 'description': 'Desc', 'show': True}
MenuOptions = Dict[str, Union[str, MenuOptionDetail]]

def normalize_string(text: str) -> str:
    """Removes accents and normalizes a string."""
    try:
        # Decompose characters into base + combining marks
        normalized = unicodedata.normalize('NFD', text)
        # Filter out combining marks (Mn category)
        return ''.join(c for c in normalized if unicodedata.category(c) != 'Mn')
    except TypeError:
        # Handle cases where input might not be a string gracefully
        return str(text) # Or raise a specific error

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def int_to_bytes(n: int) -> bytes:
    """Converts a non-negative integer to its byte representation (big-endian)."""
    if n < 0:
        raise ValueError("Cannot convert negative integers directly to bytes this way.")
    if n == 0:
        return b'\x00'
    # Calculate bytes needed: (bit_length + 7) // 8 ensures correct rounding up
    num_bytes = (n.bit_length() + 7) // 8
    return n.to_bytes(num_bytes, byteorder='big')

class MinitelUI:
    """Handles Minitel-like terminal interactions."""

    def __init__(self, screen_width: int = MINITEL_SCREEN_WHIDTH, default_delay: float = DEFAULT_SLOW_PRINT_DELAY):
        self.screen_width = screen_width
        self.default_delay = default_delay

    def _pad_line(self, line: str) -> str:
        """Pads a single line with spaces to fit the screen width."""
        return line.ljust(self.screen_width)

    def pad_to_screen_(self, text: str) -> str:
        """Pads each line of a potentially multi-line string to the screen width."""
        lines = text.splitlines() # Handles different newline characters
        padded_lines = [self._pad_line(line) for line in lines]
        return "\n".join(padded_lines)

    def slow_print_(self, text: str, delay: Optional[float] = None, add_new_line: bool = True):
        """Prints text character by character with a delay."""
        # Normalize text before printing
        if delay is None:
            delay = self.default_delay
        normalized_text = normalize_string(text)
        for char in normalized_text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        if add_new_line:
            print() # Adds a newline at the end
            
    def print(self, text: str, delay: Optional[float] = None, add_new_line: bool = True, pad_to_streen: bool = True):
        if pad_to_streen:
            text = self.pad_to_screen_(text)
        self.slow_print_(text, delay=delay, add_new_line=add_new_line)

    def display_new_screen(self, header_info: str = COST_PER_MINUTE_INFO):
        """Clears the screen and displays the standard header."""
        clear_screen()
        # Assume get_logo_header_screen incorporates the header_info
        logo_header = get_logo_header_screen(header_info)
        self.print(logo_header, add_new_line=True) # Ensure newline after header

    def display_menu(self, title: str, options: MenuOptions):
        """Displays a numbered menu from a dictionary of options."""
        self.display_new_screen() # Start with a fresh screen and header
        self.print(f"\n--- {normalize_string(title)} ---\n")

        if not options:
            self.print("Aucune option disponible.")
            return

        for key, value in options.items():
            option_text: str = ""
            description: str = ""
            display: bool = True

            if isinstance(value, dict):
                # Handle complex option structure
                detail: MenuOptionDetail = value # type checking/assertion if needed
                display = detail.get('show', True)
                if not display:
                    continue
                option_text = detail.get('option', f"Option {key}") # Default text
                description = detail.get('description', '')
            elif isinstance(value, str):
                # Handle simple option structure
                option_text = value
            else:
                # Handle unexpected type
                self.print(f"Warning: Invalid option format for key '{key}'. Skipping.")
                continue

            # Format the line
            prefix = f"{key}. {normalize_string(option_text)}"
            if description:
                prefix += f" | {normalize_string(description)}"

            # Wrap text if it exceeds screen width
            if len(prefix) > self.screen_width:
                # Initial indent same as prefix up to the first text after number
                initial_indent = " " * (len(key) + 2) # Length of "N. "
                # Subsequent indent aligns with the description or option text
                subsequent_indent = " " * (len(key) + 2)
                if description:
                     # Try to align with description if possible
                     try:
                         desc_start_col = prefix.index('|') + 2 # Position after " | "
                         subsequent_indent = " " * desc_start_col
                     except ValueError:
                         pass # Fallback to initial indent if '|' not found

                wrapped_text = textwrap.fill(
                    prefix,
                    width=self.screen_width,
                    initial_indent="", # No initial indent for the first line
                    subsequent_indent=subsequent_indent,
                    break_long_words=False, # Try not to break words
                    replace_whitespace=True # Clean up whitespace
                )
                self.print(wrapped_text, add_new_line=False)
            else:
                # Pad the single line
                self.print(self._pad_line(prefix), add_new_line=False)
            print() # Add newline after each menu item

        # Optional: Add a separator line at the end
        # print("\n" + "-" * self.screen_width)

    def get_choice(self, prompt: str, valid_choices: set[str] | list[str] | str, to_hide: set[str] | list[str] | str = None) -> str:
        """Prompts the user for input and validates it against a set of valid choices."""
        if not valid_choices:
             # Should ideally not happen if called after display_menu with options
             self.print("Erreur: Aucune option valide fournie.")
             return "" # Or raise an exception
        if isinstance(valid_choices, str):
            valid_choices = [valid_choices]
        if isinstance(to_hide, str):
            to_hide = [to_hide]
        valid_choices = sorted(list(valid_choices))
        if to_hide is not None:
            valid_options_str = ", ".join([x for x in valid_choices if x not in to_hide])
        else:
            valid_options_str = ", ".join(valid_choices)

        while True:
            self.print(prompt, add_new_line=False, pad_to_streen=False)
            choice = input(PROMPT_INDICATOR).strip()
            if choice in valid_choices:
                return choice
            else:
                # Keep the error message simple and clear
                error_msg = f"{INVALID_CHOICE_PROMPT} {PLEASE_ENTER_PROMPT}{valid_options_str}"
                # Wrap error message if too long
                self.print(textwrap.fill(error_msg, self.screen_width))

    def get_message(self, prompt: str = "Veuillez entrer le message :") -> str:
        """Clears screen, prompts user for a non-empty message, and returns it."""
        self.display_new_screen()
        while True:
            self.print(f"\n{prompt}", add_new_line=True)
            message = input(PROMPT_INDICATOR).strip()
            if message:
                return message
            else:
                self.print(self.pad_to_screen(EMPTY_MESSAGE_ERROR))

    def format_output(self, data_bytes: bytes, format_name: str) -> str:
        """Formats binary data into the specified string format."""
        formatter = SUPPORTED_FORMATS.get(format_name)
        if formatter:
            try:
                return formatter(data_bytes)
            except Exception as e:
                # Log the error potentially
                self.print(f"\nErreur lors du formatage ({format_name}): {e}", file=sys.stderr)
                return f"Erreur de formatage ({format_name})"
        else:
            # Fallback or handle unknown format
            self.print(f"\nWarning: Format '{format_name}' non reconnu. Utilisation du format par défaut.", file=sys.stderr)
            return SUPPORTED_FORMATS[FORMAT_FALLBACK](data_bytes)

    def display_result(self, info: str, result: str, keys: Optional[str] = None):
        """Displays formatted information, optional keys, and the result."""
        self.display_new_screen()
        self.print('\n') # Extra spacing
        self.print(info, add_new_line=True)
        self.print('-' * self.screen_width, add_new_line=True)
        if keys:
            self.print(keys, add_new_line=True)
        self.print(result, add_new_line=True)
        while True:
            self.print('Imprimer le resultat ? (o/n) ', add_new_line=False, pad_to_streen=False)
            choice = input()
            if choice == "o" or choice == "n":
                return choice
            else:
                self.print("Choix invalide choisir o pour oui et n pour non.", add_new_line=False)

    def confirm_action(self, prompt: str) -> bool:
        """Asks a yes/no question and returns True for 'o' (oui) and False for 'n' (non)."""
        prompt_normalized = normalize_string(prompt)
        while True:
            self.print(prompt_normalized, add_new_line=False)
            choice = input(PROMPT_INDICATOR).strip().lower()
            if choice == 'o':
                return True
            elif choice == 'n':
                return False
            else:
                self.print(INVALID_PRINT_CHOICE) # Reusing this constant, maybe rename
                
    def select_print_speed(self):
        # Define menu options with associated delay values
        speed_options: MenuOptions = {
            '1': {'option': 'Lent', 'description': '(Minitel 1)', 'delay': SPEED_SLOW},
            '2': {'option': 'Moyen', 'description': '(Minitel 1B+)', 'delay': SPEED_MEDIUM},
            '3': {'option': 'Rapide', 'description': '(Minitel 2+)', 'delay': SPEED_FAST},
            '4': {'option': 'Temps réel', 'description': '(Instantané)', 'delay': SPEED_INSTANT}
        }
        self.display_menu("Choisir la vitesse d'affichage", speed_options)

        valid_choices = set(speed_options.keys())
        choice_key = self.get_choice("Votre choix ?", valid_choices)
        
        # Get the selected option details (which is a dict in this case)
        selected_option = speed_options[choice_key]
        if isinstance(selected_option, dict):
            new_delay = selected_option.get('delay', self.default_delay) # Get delay, fallback to current
            self.default_delay = new_delay # Update instance's default delay
            self.print(f"{SPEED_UPDATED_MSG} (Mode: {selected_option.get('option', 'Inconnu')})")
            time.sleep(1) # Pause briefly to show the confirmation
        else:
            # Should not happen if menu is structured correctly
             self.print("Erreur: Impossible de déterminer la vitesse sélectionnée.")
             time.sleep(1)
        

# --- Menu Preparation Logic (Could be part of a larger application structure) ---

def prepare_menu_options(options_list: list[dict[str, Any]]) -> MenuOptions:
    """
    Filters a list of option dictionaries based on the 'show' key
    and prepares it for the display_menu function.
    Example input item: {'option': 'Do X', 'description': 'Runs X', 'show': True, 'action': 'do_x'}
    """
    numbered_options: MenuOptions = {}
    current_number = 1
    for item in options_list:
        # Ensure item is a dict and has the 'show' key correctly
        if isinstance(item, dict) and item.get('show', False):
            # We can pass the whole dict or just relevant parts
            # Passing the whole dict simplifies display_menu if it needs other keys later
            numbered_options[str(current_number)] = item
            current_number += 1
    return numbered_options