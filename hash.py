import yaml
from escpos.printer import LP
import sys

from ui import *
from config_loader import load_config
from logs import write_counters, read_counters
from config import *
from crypto import *
from printer import *

sys.set_int_max_str_digits(10_000)

# --- Globals ---
PRINTER = LP(printer_name=PRINTER_NAME, autoflush=True)
N_USE, N_PRINT = read_counters(COUNTER_FILE)

def run():
    try:
        with open('./config.yaml', 'r') as in_file:
            options = yaml.load(in_file, Loader=yaml.SafeLoader)
    except FileNotFoundError:
        print(f"Error: The file 'config.ymal' was not found.")
    except yaml.YAMLError as e:
        print(f"Error loading YAML file: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")    
    
    ui = MinitelUI(default_delay=0)
    while True:
        message = ui.get_message("Calcul une empreinte numerique en utilisant l'algorithme SHA 256.\n\nEntrer le message :")
        if message == QUIT_STR:
            write_counters(COUNTER_FILE, N_USE, N_PRINT)
            ui.display_new_screen()
            ui.print("             Merci d'avoir utilise l'application de chiffrement!")
            return
        elif message == SPEED_OPTION_MENU_STR:
            ui.select_print_speed()
        else:
            res = compute_hashes(message, 'SHA-2 256')
            def gen_results(message, algo_name, algo_description, print_format, max_width, res, ticket = False):
                print_infos = f"Algorithme : {algo_name}\n"
                prefix = "Info : "
                info_line = prefix+f"{algo_description}\n"
                print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                print_infos += '\n'
                print_infos += f"Format d'affichage : {print_format}\n"
                print_infos += f"Message : {message}\n"
                
                print_res = "EPREINTE NUMERIQUE (HASH) DU MESSAGE\n"
                res_formatted = ui.format_output(res, print_format)
                if print_format != "Carte perforee":
                    if ticket:
                        print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                else:
                    print_res += res_formatted
                    print_res += "\n"
                return print_infos, print_res
    
            algo_description = "Algorithme de hachage, genere une empreinte numerique unique de 256 bits."
            print_infos, print_res = gen_results(message, "SHA2-256", algo_description, "Carte perforee", MINITEL_SCREEN_WHIDTH, res)
                
            to_print = ui.display_result(print_infos, print_res)
            if to_print == "o":
                print_infos, print_res = gen_results(message, "SHA2-256", algo_description, "Carte perforee", PRINTER_WIDTH, res, True)
                print_ticket(PRINTER,print_infos, print_res)
            ui.print("\nAppuyez sur entree pour conitnuer ...")
            input()
    
if __name__ == "__main__":
    run()