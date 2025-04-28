import yaml
import importlib
from escpos.printer import LP

from ui import *
from config_loader import load_config
from logs import write_counters, read_counters
from config import *
from crypto import *
from printer import *

# --- Globals ---
PRINTER = LP(printer_name=PRINTER_NAME, autoflush=True)
N_USE, N_PRINT = read_counters(COUNTER_FILE)

# --- Boucle Principale ---
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
    #print(options)
    #return
    algorithms = list()
    for k, v in options['algorithms'].items():
        tmp = {"option": k}
        for x in v:
            tmp.update(x)
        algorithms.append(tmp)
    algorithms_options = get_options(algorithms)
    while True:
        display_menu('Choisissez un algorithme !', algorithms_options)
        choice = get_choice("Votre choix : ", list(algorithms_options.keys())+[QUIT_STR], [QUIT_STR])
        if choice == QUIT_STR:
            write_counters(COUNTER_FILE, N_USE, N_PRINT)
            new_screen()
            print("             Merci d'avoir utilise l'application de chiffrement!")
            return
        else:
            algo_name = algorithms_options[choice]['option']
            algo_description = algorithms_options[choice]['description']
            for x in options[algo_name]:
                if 'title' in x:
                    title = x['title']
                if 'print_options' in x:
                    print_options = get_options(x['print_options'])
            
            algo_options = get_options([x for x in options[algo_name] if 'option' in x])            
            display_menu(title, algo_options)
            choice = get_choice("Votre choix : ", list(algo_options.keys()))
            key_param = algo_options[choice]['option']
            message = get_message()
            display_menu("Choisissez le format d'affichage.", print_options)
            choice = get_choice("Votre choix : ", list(print_options.keys()))
            print_format = print_options[choice]['option']
            if algo_name == 'AES':
                key_size = int(key_param.split(' ')[0])
                res, key = encrypt_aes(message, key_size)
                
                def gen_results(algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                
                    print_key = ""
                    for k, v in key.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if ticket:
                            v_formatted = textwrap.fill(format_output(v, print_format).replace(' ', ''), max_width)
                        else:
                            v_formatted = textwrap.fill(format_output(v, print_format), max_width)
                        print_key += v_formatted
                        print_key += "\n"
                
                    print_res = "MESSAGE CHIFFRE\n"
                    res_formatted = format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                to_print = display_res(print_infos, print_res, print_key)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    print_ticket(print_infos, print_res, print_key)
                
            elif algo_name == 'ChaCha20':
                key_size = int(key_param.split(' ')[0])
                res, key = encrypt_chacha20(message, key_size)
                
                def gen_results(algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                
                    print_key = ""
                    for k, v in key.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if ticket:
                            v_formatted = textwrap.fill(format_output(v, print_format).replace(' ', ''), max_width)
                        else:
                            v_formatted = textwrap.fill(format_output(v, print_format), max_width)
                        print_key += v_formatted
                        print_key += "\n"
                
                    print_res = "MESSAGE CHIFFRE\n"
                    res_formatted = format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                to_print = display_res(print_infos, print_res, print_key)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    print_ticket(print_infos, print_res, print_key)
                
            elif algo_name == 'SHA':
                res = compute_hashes(message, key_param)
                
                def gen_results(algo_name, algo_description, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Format d'affichage : {print_format}\n"
                
                    print_res = "EPREINTE NUMERIQUE (HASH) DU MESSAGE\n"
                    res_formatted = format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res
                
                print_infos, print_res = gen_results(algo_name, algo_description, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                to_print = display_res(print_infos, print_res)
                if to_print == "o":
                    print_infos, print_res = gen_results(algo_name, algo_description, print_format, PRINTER_WIDTH, res, True)
                    print_ticket(print_infos, print_res)
                    
            elif algo_name == 'ECC':
                res, _, key_elemnts = encrypt_ecc(message, key_param)
                
                def gen_results(algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                
                    print_key = ""
                    for k, v in key_elemnts.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_key += kk+" : "
                                print_key +='\n'
                                if ticket:
                                    print_key += textwrap.fill(format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_key += textwrap.fill(format_output(vv, print_format), max_width)
                                print_key += "\n"
                        else:
                            if ticket:
                                print_key += textwrap.fill(format_output(v, print_format).replace(' ', ''), max_width)
                                print_key += "\n"
                            else:
                                print_key += textwrap.fill(format_output(v, print_format), max_width)
                                print_key += "\n"
                            print_key += "\n"
                        print_key += "\n"
                
                    print_res = "MESSAGE CHIFFRE\n"
                    res_formatted = format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                to_print = display_res(print_infos, print_res, print_key)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    print_ticket(print_infos, print_res, print_key)
            elif algo_name == 'RSA':
                key_size = int(key_param.split(' ')[0])
                res, _, key_elemnts = encrypt_rsa(message, key_size)
                
                def gen_results(algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                
                    print_key = ""
                    for k, v in key_elemnts.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_key += kk+" : "
                                print_key +='\n'
                                if ticket:
                                    print_key += textwrap.fill(format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_key += textwrap.fill(format_output(vv, print_format), max_width)
                                print_key += "\n"
                        else:
                            if ticket:
                                print_key += textwrap.fill(format_output(v, print_format).replace(' ', ''), max_width)
                                print_key += "\n"
                            else:
                                print_key += textwrap.fill(format_output(v, print_format), max_width)
                                print_key += "\n"
                            print_key += "\n"
                        print_key += "\n"
                
                    print_res = "MESSAGE CHIFFRE\n"
                    res_formatted = format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                to_print = display_res(print_infos, print_res, print_key)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    print_ticket(print_infos, print_res, print_key)
            elif algo_name == "Kyber":
                res, keys_elements = kyber_encrypt(message, key_param)
                
                def gen_results(algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                
                    print_key = ""
                    for k, v in keys_elements.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_key += kk+" : "
                                print_key +='\n'
                                if ticket:
                                    print_key += textwrap.fill(format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_key += textwrap.fill(format_output(vv, print_format), max_width)
                                print_key += "\n"
                        else:
                            if ticket:
                                print_key += textwrap.fill(format_output(v, print_format).replace(' ', ''), max_width)
                                print_key += "\n"
                            else:
                                print_key += textwrap.fill(format_output(v, print_format), max_width)
                                print_key += "\n"
                            print_key += "\n"
                        print_key += "\n"
                    print_res = ""
                    for k, v in res.items():
                        print_res += k.upper()
                        print_res += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_res += kk+" : "
                                print_res +='\n'
                                if ticket:
                                    print_res += textwrap.fill(format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_res += textwrap.fill(format_output(vv, print_format), max_width)
                                print_res += "\n"
                        else:
                            if ticket:
                                print_res += textwrap.fill(format_output(v, print_format).replace(' ', ''), max_width)
                                print_res += "\n"
                            else:
                                print_res += textwrap.fill(format_output(v, print_format), max_width)
                                print_res += "\n"
                            print_res += "\n"
                        print_res += "\n"
                    return print_infos, print_res, print_key
                
                print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                to_print = display_res(print_infos, print_res, print_key)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    print_ticket(print_infos, print_res, print_key)
            input("Appuyez sur entrée pour conitnuer ...")
            

if __name__ == "__main__":
    # Initialiser PRINTER ici si ce n'est pas déjà fait globalement
    run()