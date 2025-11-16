import yaml
from escpos.printer import LP
import sys
import json 
import time
import signal

from ui import *
from config_loader import load_config
from logs import write_counters, read_counters
from config import MINITEL_SCREEN_WIDTH, QUIT_STR, SPEED_OPTION_MENU_STR, PRINTER_NAME
from crypto import *
from printer import *

sys.set_int_max_str_digits(10_000)

# --- Globals ---
PRINTER = LP(printer_name=PRINTER_NAME, autoflush=True)
# N_USE, N_PRINT = read_counters(COUNTER_FILE)
PRINT_FORMAT_OPTIONS = [FORMAT_BIN, FORMAT_DEC, FORMAT_HEX, FORMAT_B64]
PRINT_FORMAT = PRINT_FORMAT_OPTIONS[1]
MENU_TIMEOUT_SECONDS = 15  # Timeout for menu selection in seconds

ALGORITHMS = {
    'aes': {"description": "Algorithme cryptographique symétrique. Utilisé pour le chiffrement de fichiers, WiFi, VPN, HTTPS, Signal, etc."},
    'rsa': {"description": "Algorithme cryptographique asymétrique reposant sur la factorisation d'entiers. Utilisé pour HTTPS, signatures de documents, chiffrement de mails, carte à puces, PKI, etc."},
    'ecc': {"description": "Algorithme cryptographique asymétrique sur courbes elliptiques. Utilisé pour HTTPS, signatures de documents, chiffrement de mails, carte à puces, blockchain, etc."},
    'kyber': {"description": "Algorithme cryptographique post-quantique basé sur les réseaux euclidiens. Utilisé Apple iMessage, Signal, HTTPS experimental (TLS 1.3)."},
}

try:
    with open('perfs.json', 'r') as in_file:
        PERFS = json.load(in_file)
except (FileNotFoundError, json.JSONDecodeError) as e:
    print(f"Error loading perfs.json: {e}")


def get_rand_range_val(val):
    min_val = val - val*0.1
    max_val = val + val*0.1
    return random.uniform(min_val, max_val)

def estimate_footprint(time_s, tdp):
    W = tdp*(time_s/3600.0)
    kWh = W/1000.0
    footprint = kWh*32.0
    return W, footprint

def get_estimate(time_us):
    t_us = get_rand_range_val(time_us)
    t_s = t_us/1_000_000
    w, c = estimate_footprint(t_s, 12)
    return t_s, w, c

def timeout_handler(signum, frame):
    raise TimeoutError

def gen_results(ui, message: str, algo_name: str, algo_description:str,
                key_infos: str|int, keys: Dict, ciphertext: Dict|str|bytes,
                max_width: int, ticket = False):
    print_infos = f"Algorithme : {algo_name}\n"
    prefix = "Info : "
    info_line = prefix+f"{algo_description}\n"
    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
    print_infos += '\n'
    print_infos += f"Informations sur la clé : {key_infos}\n"
    print_infos += "Niveau de sécurité estimé : 128 bits\n"
    # print_infos += f"Format d'affichage : {print_format}\n"
    print_infos += f"Message clair : {message}\n"
    
    print_key = ""
    for k, v in keys.items():
        print_key += k.upper()
        print_key += "\n"
        if isinstance(v, dict):
            for kk, vv in v.items():
                print_key += kk.lower() + "\n"
                # Convert to bytes if it's a string or int
                if isinstance(vv, str):
                    vv_bytes = vv.encode('utf-8')
                elif isinstance(vv, int):
                    vv_bytes = int_to_bytes(vv)
                elif isinstance(vv, bytes):
                    vv_bytes = vv
                else:
                    vv_bytes = str(vv).encode('utf-8')
                    
                if ticket:
                    v_formatted = textwrap.fill(ui.format_output(vv_bytes, PRINT_FORMAT).replace(' ', ''), max_width)
                else:
                    v_formatted = textwrap.fill(ui.format_output(vv_bytes, PRINT_FORMAT), max_width)
                print_key += v_formatted
                print_key += "\n"
        else:
            if ticket:
                v_formatted = textwrap.fill(ui.format_output(v, PRINT_FORMAT).replace(' ', ''), max_width)
            else:
                v_formatted = textwrap.fill(ui.format_output(v, PRINT_FORMAT), max_width)
            print_key += v_formatted
            print_key += "\n"
        print_key += "\n"
                
    
    if isinstance(ciphertext, dict):
        print_res = ""
        for k, v in ciphertext.items():
            print_res += k.upper() + "\n"
            if ticket:
                v_formatted = textwrap.fill(ui.format_output(v, PRINT_FORMAT).replace(' ', ''), max_width)
            else:
                v_formatted = textwrap.fill(ui.format_output(v, PRINT_FORMAT), max_width)
            print_res += v_formatted
            print_res += "\n\n"
    else:
        print_res = "\nMESSAGE CHIFFRE :\n"
        res_formatted = ui.format_output(ciphertext, PRINT_FORMAT)
        if ticket:
            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
        else:
            print_res += textwrap.fill(res_formatted, max_width)
        print_res += "\n"
    return print_infos, print_res, print_key


def gen_energy_footprint(algo_name, key_param, max_width):
    tkg, wkg, ckg = get_estimate(PERFS[algo_name][key_param]['keygen']['time'])
    tke, wke, cke = get_estimate(PERFS[algo_name][key_param]['encrypt']['time'])
    t = tkg+tke
    w = wkg + wke
    c = ckg + cke
    if max_width == PRINTER_WIDTH:
        t_str = f"{t:.7f}"
        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
        energy = "Cout energetique \n"
        w_str = f"{w:.12f}"
        c_str = f"{c:.12f}"
        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
    else:
        execution_time = f"Temps de calcul  : {t:.7f} s\n"
        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
    return execution_time + energy

def gen_compute_time(algo_name, max_width):
    compute_time = "Temps pour casser la clé avec un supercalculateur (1) : 6 190 000 000 000 ans\n"
    if algo_name == 'aes':
        compute_time += "Temps pour casser la clé avec un ordinateur quantique (2) : 6 190 000 ans\n\n"
    elif algo_name == 'rsa':
        compute_time += "Temps pour casser la clé avec un ordinateur quantique (2) : 27 heures\n\n"
    elif algo_name == 'ecc':
        compute_time += "Temps pour casser la clé avec un ordinateur quantique (2) : 395 heures (16.5 jours)\n\n"
    elif algo_name == 'kyber':
        compute_time += "Temps pour casser la clé avec un ordinateur quantique (2) : 1.2*10^(26) ans\n\n"
        
    compute_time += textwrap.fill("(1) Supercalculateur El Capitan 10^18 operations / second", max_width)
    compute_time += "\n"
    compute_time += textwrap.fill("(2) Ordinateur quantique theorique 2 000 000 qbits, 90 000 operations / second", max_width)
    compute_time += "\n"
    return compute_time

def run():
    try:
        with open('./config.yaml', 'r') as in_file:
            options = yaml.load(in_file, Loader=yaml.SafeLoader)
    except FileNotFoundError:
        print(f"Error: The file 'config.yaml' was not found.")
        return  # Exit gracefully instead of continuing with undefined 'options'
    except yaml.YAMLError as e:
        print(f"Error loading YAML file: {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return
    
    ui = MinitelUI(default_delay=0.0008)
    
    algorithms = list()
    for k, v in options['algorithms'].items():
        tmp = {"option": k}
        for x in v:
            tmp.update(x)
        algorithms.append(tmp)
    algorithms_options = prepare_menu_options(algorithms)
    
    while True:
        ui.display_menu('Choisissez un algorithme !', algorithms_options)
        choice = None    
        
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(MENU_TIMEOUT_SECONDS)  
        try:
            choice = ui.get_choice("Votre choix : ", list(algorithms_options.keys())+[QUIT_STR, SPEED_OPTION_MENU_STR]+["aes", "rsa", "ecc", "kyber"], [QUIT_STR, SPEED_OPTION_MENU_STR])
        except TimeoutError:
            choice = None  # Timeout occurred, show menu again
        except KeyboardInterrupt:
            choice = QUIT_STR  # Handle Ctrl+C gracefully
        finally:
            signal.alarm(0)  # Always disable the alarm
        
        if choice == QUIT_STR:
            # write_counters(COUNTER_FILE, N_USE, N_PRINT)
            ui.display_new_screen()
            ui.print("             Merci d'avoir utilise 3615 Crypto !\n")
            return
        elif choice == SPEED_OPTION_MENU_STR:
            ui.select_print_speed()
        elif choice is None:
            continue  # Timeout or no valid choice, show menu again
        choice = choice.lower()
        message = ui.get_message()
        if choice == '1' or choice == 'aes':
            ciphertext, keys = encrypt_aes(message, key_size=128)
            
            print_infos, print_res, print_key = gen_results(ui, message, "AES", ALGORITHMS['aes']['description'], "128 bits", keys, ciphertext, MINITEL_SCREEN_WIDTH)
            energy = gen_energy_footprint("AES", "128 bits", MINITEL_SCREEN_WIDTH)
            compute_time = gen_compute_time("aes", MINITEL_SCREEN_WIDTH)
            print_ticket_choice = ui.display_result(print_infos, print_res, print_key, energy=energy, compute_time=compute_time)
            if print_ticket_choice:
                print_infos, print_res, print_key = gen_results(ui, message, "AES", ALGORITHMS['aes']['description'], "128 bits", keys, ciphertext, PRINTER_WIDTH, True)
                # print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                energy_footprint = gen_energy_footprint("AES", "128 bits", PRINTER_WIDTH)
                compute_time = gen_compute_time("aes", PRINTER_WIDTH)
                print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint, compute_time=compute_time)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            # print(f"AES Encryption completed. Ciphertext length: {len(ciphertext)} bytes")
        elif choice == '2' or choice == 'rsa':
            ciphertext, keys_dict, structured_components = encrypt_rsa(message, key_size=3072)
            
            print_infos, print_res, print_key = gen_results(ui, message, "RSA", ALGORITHMS['rsa']['description'], "3072 bits\n n = p * q    d = e^-1 mod phi(n)", structured_components, ciphertext, MINITEL_SCREEN_WIDTH)
            energy = gen_energy_footprint("RSA", "3072 bits", MINITEL_SCREEN_WIDTH)
            compute_time = gen_compute_time("rsa", MINITEL_SCREEN_WIDTH)
            print_ticket_choice = ui.display_result(print_infos, print_res, print_key, energy=energy, compute_time=compute_time)
            if print_ticket_choice:
                print_infos, print_res, print_key = gen_results(ui, message, "RSA", ALGORITHMS['rsa']['description'], "3072 bits\n n = p * q    d = e^-1 mod phi(n)", structured_components, ciphertext, PRINTER_WIDTH, True)
                energy_footprint = gen_energy_footprint("RSA", "3072 bits", PRINTER_WIDTH)
                compute_time = gen_compute_time("rsa", PRINTER_WIDTH)
                print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint, compute_time=compute_time)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            
            # print(f"RSA Encryption completed. Ciphertext length: {len(ciphertext)} bytes")
        elif choice == '3' or choice == 'ecc':
            encrypted_data, keys, keys_elements = encrypt_ecc(message, curve_name="SECP 256 R1")
            
            print_infos, print_res, print_key = gen_results(ui, message, "ECC", ALGORITHMS['ecc']['description'], "256 bits\n  Courbe : SECP 256 R1", keys_elements, encrypted_data, MINITEL_SCREEN_WIDTH)
            energy = gen_energy_footprint("ECC", "SECP 256 R1", MINITEL_SCREEN_WIDTH)
            compute_time = gen_compute_time("ecc", MINITEL_SCREEN_WIDTH)
            print_ticket_choice = ui.display_result(print_infos, print_res, print_key, energy=energy, compute_time=compute_time)
            if print_ticket_choice:
                print_infos, print_res, print_key = gen_results(ui, message, "ECC", ALGORITHMS['ecc']['description'], "256 bits\n  Courbe : SECP 256 R1", keys_elements, encrypted_data, PRINTER_WIDTH, True)
                energy_footprint = gen_energy_footprint("ECC", "SECP 256 R1", PRINTER_WIDTH)
                compute_time = gen_compute_time("ecc", PRINTER_WIDTH)
                print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint, compute_time=compute_time)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            # print(f"ECC Encryption completed. Ciphertext length: {len(encrypted_data)} bytes")
        elif choice == '4' or choice == 'kyber':
            ciphertext_dict, keys_dict = kyber_encrypt(message, key_param="ML-KEM-512")
            
            print_infos, print_res, print_key = gen_results(ui, message, "KYBER", ALGORITHMS['kyber']['description'], "ML-KEM-512", keys_dict, ciphertext_dict, MINITEL_SCREEN_WIDTH)
            energy = gen_energy_footprint("Kyber", "ML-KEM-512", MINITEL_SCREEN_WIDTH)
            compute_time = gen_compute_time("kyber", MINITEL_SCREEN_WIDTH)
            print_ticket_choice = ui.display_result(print_infos, print_res, print_key, energy=energy, compute_time=compute_time)
            if print_ticket_choice:
                print_infos, print_res, print_key = gen_results(ui, message, "KYBER", ALGORITHMS['kyber']['description'], "ML-KEM-512", keys_dict, ciphertext_dict, PRINTER_WIDTH, True)
                energy_footprint = gen_energy_footprint("Kyber", "ML-KEM-512", PRINTER_WIDTH)
                compute_time = gen_compute_time("kyber", PRINTER_WIDTH)
                print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint, compute_time=compute_time)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            # print(f"Kyber Encryption completed.")
        

if __name__ == "__main__":
    run()