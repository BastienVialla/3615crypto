import yaml
from escpos.printer import LP
import sys
import json 

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
        
    with open('perfs.json', 'r') as in_file:
        perfs = json.load(in_file)
    
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
        choice = ui.get_choice("Votre choix : ", list(algorithms_options.keys())+[QUIT_STR, SPEED_OPTION_MENU_STR], [QUIT_STR, SPEED_OPTION_MENU_STR])
        if choice == QUIT_STR:
            write_counters(COUNTER_FILE, N_USE, N_PRINT)
            ui.display_new_screen()
            ui.print("             Merci d'avoir utilise l'application de chiffrement!")
            return
        if choice == SPEED_OPTION_MENU_STR:
            ui.select_print_speed()
        else:
            algo_name = algorithms_options[choice]['option']
            algo_description = algorithms_options[choice]['description']
            for x in options[algo_name]:
                if 'title' in x:
                    title = x['title']
                if 'print_options' in x:
                    print_options = prepare_menu_options(x['print_options'])
            
            algo_options = prepare_menu_options([x for x in options[algo_name] if 'option' in x])            
            ui.display_menu(title, algo_options)
            choice = ui.get_choice("Votre choix : ", list(algo_options.keys()))
            key_param = algo_options[choice]['option']
            message = ui.get_message()
            ui.display_menu("Choisissez le format d'affichage.", print_options)
            choice = ui.get_choice("Votre choix : ", list(print_options.keys()))
            print_format = print_options[choice]['option']
            if algo_name == 'AES':
                key_size = int(key_param.split(' ')[0])
                res, key = encrypt_aes(message, key_size)
                
                def gen_results(message, algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                    print_infos += f"Message : {message}\n"
                
                    print_key = ""
                    for k, v in key.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if ticket:
                            v_formatted = textwrap.fill(ui.format_output(v, print_format).replace(' ', ''), max_width)
                        else:
                            v_formatted = textwrap.fill(ui.format_output(v, print_format), max_width)
                        print_key += v_formatted
                        print_key += "\n"
                
                    print_res = "\nMESSAGE CHIFFRE\n"
                    res_formatted = ui.format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                def gen_energy_footprint(algo_name, key_param, max_width):
                    tkg, wkg, ckg = get_estimate(perfs[algo_name][key_param]['keygen']['time'])
                    tke, wke, cke = get_estimate(perfs[algo_name][key_param]['encrypt']['time'])
                    t = tkg+tke
                    w = wkg + wke
                    c = ckg + cke
                    if max_width == PRINTER_WIDTH:
                        t_str = f"{t:.12f}"
                        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
                        energy = "Cout energetique \n"
                        w_str = f"{w:.12f}"
                        c_str = f"{c:.12f}"
                        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
                        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
                    else:
                        execution_time = f"Temps de calcul  : {t:.12f} s\n"
                        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
                    return execution_time + energy
                
                print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                energy = gen_energy_footprint(algo_name, key_param, MINITEL_SCREEN_WHIDTH)
                to_print = ui.display_result(print_infos, print_res, print_key, energy)
                #return
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    energy_footprint = gen_energy_footprint(algo_name, key_param, PRINTER_WIDTH)
                    print_ticket(PRINTER, print_infos, print_res, print_key, energy=energy_footprint)
                    
                    # t = print_ticket_(PRINTER, print_infos, print_res, print_key, energy=energy)
                    # print(t)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
                
            elif algo_name == 'ChaCha20':
                key_size = int(key_param.split(' ')[0])
                res, key = encrypt_chacha20(message, key_size)
                
                def gen_results(message, algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                    print_infos += f"Message : {message}\n"
                
                    print_key = ""
                    for k, v in key.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if ticket:
                            v_formatted = textwrap.fill(ui.format_output(v, print_format).replace(' ', ''), max_width)
                        else:
                            v_formatted = textwrap.fill(ui.format_output(v, print_format), max_width)
                        print_key += v_formatted
                        print_key += "\n"
                
                    print_res = "\nMESSAGE CHIFFRE\n"
                    res_formatted = ui.format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                def gen_energy_footprint(algo_name, key_param, max_width):
                    tkg, wkg, ckg = get_estimate(perfs[algo_name][key_param]['keygen']['time'])
                    tke, wke, cke = get_estimate(perfs[algo_name][key_param]['encrypt']['time'])
                    t = tkg+tke
                    w = wkg + wke
                    c = ckg + cke
                    if max_width == PRINTER_WIDTH:
                        t_str = f"{t:.12f}"
                        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
                        energy = "Cout energetique \n"
                        w_str = f"{w:.12f}"
                        c_str = f"{c:.12f}"
                        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
                        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
                    else:
                        execution_time = f"Temps de calcul  : {t:.12f} s\n"
                        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
                    return execution_time + energy
                
                print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                energy_footprint = gen_energy_footprint(algo_name, key_param, MINITEL_SCREEN_WHIDTH)
                to_print = ui.display_result(print_infos, print_res, print_key, energy_footprint)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    energy_footprint = gen_energy_footprint(algo_name, key_param, PRINTER_WIDTH)
                    print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint)
                    
                    # t = print_ticket_(PRINTER, print_infos, print_res, print_key, energy_footprint)
                    # print(t)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
                
            elif algo_name == 'SHA':
                res = compute_hashes(message, key_param)
                
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
                
                def gen_energy_footprint(algo_name, key_param, max_width):
                    tkg, wkg, ckg = get_estimate(perfs[algo_name][key_param]['time'])
                    t = tkg
                    w = wkg
                    c = ckg
                    if max_width == PRINTER_WIDTH:
                        t_str = f"{t:.12f}"
                        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
                        energy = "Cout energetique \n"
                        w_str = f"{w:.12f}"
                        c_str = f"{c:.12f}"
                        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
                        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
                    else:
                        execution_time = f"Temps de calcul  : {t:.12f} s\n"
                        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
                    return execution_time + energy
                
                print_infos, print_res = gen_results(message, algo_name, algo_description, print_format, MINITEL_SCREEN_WHIDTH, res)
                energy_footprint = gen_energy_footprint(algo_name, key_param, MINITEL_SCREEN_WHIDTH)
                
                to_print = ui.display_result(print_infos, print_res, energy=energy_footprint)
                if to_print == "o":
                    print_infos, print_res = gen_results(message, algo_name, algo_description, print_format, PRINTER_WIDTH, res, True)
                    energy_footprint = gen_energy_footprint(algo_name, key_param, PRINTER_WIDTH)
                    print_ticket(PRINTER,print_infos, print_res, energy=energy_footprint)
                    # t = print_ticket_(PRINTER,print_infos, print_res, energy=energy_footprint)
                    # print(t)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
                    
            elif algo_name == 'ECC':
                res, _, key_elemnts = encrypt_ecc(message, key_param)
                
                def gen_results(message, algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                    print_infos += f"Message : {message}\n"
                
                    print_key = ""
                    for k, v in key_elemnts.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_key += kk+" : "
                                print_key +='\n'
                                if ticket:
                                    print_key += textwrap.fill(ui.format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_key += textwrap.fill(ui.format_output(vv, print_format), max_width)
                                print_key += "\n"
                        else:
                            if ticket:
                                print_key += textwrap.fill(ui.format_output(v, print_format).replace(' ', ''), max_width)
                                print_key += "\n"
                            else:
                                print_key += textwrap.fill(ui.format_output(v, print_format), max_width)
                                print_key += "\n"
                            print_key += "\n"
                        print_key += "\n"
                
                    print_res = "MESSAGE CHIFFRE\n"
                    res_formatted = ui.format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                def gen_energy_footprint(algo_name, key_param, max_width):
                    tkg, wkg, ckg = get_estimate(perfs[algo_name][key_param]['keygen']['time'])
                    tke, wke, cke = get_estimate(perfs[algo_name][key_param]['encrypt']['time'])
                    t = tkg+tke
                    w = wkg + wke
                    c = ckg + cke
                    if max_width == PRINTER_WIDTH:
                        t_str = f"{t:.12f}"
                        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
                        energy = "Cout energetique \n"
                        w_str = f"{w:.12f}"
                        c_str = f"{c:.12f}"
                        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
                        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
                    else:
                        execution_time = f"Temps de calcul  : {t:.12f} s\n"
                        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
                    return execution_time + energy
                
                print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                energy_footprint = gen_energy_footprint(algo_name, key_param, MINITEL_SCREEN_WHIDTH)
                to_print = ui.display_result(print_infos, print_res, print_key, energy_footprint)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    energy_footprint = gen_energy_footprint(algo_name, key_param, PRINTER_WIDTH)
                    print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint)
                    
                    # t = print_ticket_(PRINTER, print_infos, print_res, print_key, energy_footprint)
                    # print(t)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            elif algo_name == 'RSA':
                key_size = int(key_param.split(' ')[0])
                res, _, key_elemnts = encrypt_rsa(message, key_size)
                
                def gen_results(message, algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                    print_infos += f"Message : {message}\n"
                
                    print_key = ""
                    for k, v in key_elemnts.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_key += kk+" : "
                                print_key +='\n'
                                if ticket:
                                    print_key += textwrap.fill(ui.format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_key += textwrap.fill(ui.format_output(vv, print_format), max_width)
                                print_key += "\n"
                        else:
                            if ticket:
                                print_key += textwrap.fill(ui.format_output(v, print_format).replace(' ', ''), max_width)
                                print_key += "\n"
                            else:
                                print_key += textwrap.fill(ui.format_output(v, print_format), max_width)
                                print_key += "\n"
                            print_key += "\n"
                        print_key += "\n"   
                
                    print_res = "MESSAGE CHIFFRE\n"
                    res_formatted = ui.format_output(res, print_format)
                    if ticket:
                            print_res += textwrap.fill(res_formatted.replace(' ', ''), max_width)
                    else:
                        print_res += textwrap.fill(res_formatted, max_width)
                    print_res += "\n"
                    return print_infos, print_res, print_key
                
                def gen_energy_footprint(algo_name, key_param, max_width):
                    tkg, wkg, ckg = get_estimate(perfs[algo_name][key_param]['keygen']['time'])
                    tke, wke, cke = get_estimate(perfs[algo_name][key_param]['encrypt']['time'])
                    t = tkg+tke
                    w = wkg + wke
                    c = ckg + cke
                    if max_width == PRINTER_WIDTH:
                        t_str = f"{t:.12f}"
                        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
                        energy = "Cout energetique \n"
                        w_str = f"{w:.12f}"
                        c_str = f"{c:.12f}"
                        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
                        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
                    else:
                        execution_time = f"Temps de calcul  : {t:.12f} s\n"
                        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
                    return execution_time + energy
                
                print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                energy_footprint = gen_energy_footprint(algo_name, key_param, MINITEL_SCREEN_WHIDTH)
                to_print = ui.display_result(print_infos, print_res, print_key, energy_footprint)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    energy_footprint = gen_energy_footprint(algo_name, key_param, PRINTER_WIDTH)
                    print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint)
                    # t = print_ticket_(PRINTER, print_infos, print_res, print_key, energy_footprint)
                    # print(t)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            elif algo_name == "Kyber":
                res, keys_elements = kyber_encrypt(message, key_param)
                
                def gen_results(message, algo_name, algo_description, key_param, print_format, max_width, res, ticket = False):
                    print_infos = f"Algorithme : {algo_name}\n"
                    prefix = "Info : "
                    info_line = prefix+f"{algo_description}\n"
                    print_infos += textwrap.fill(info_line, max_width, subsequent_indent=" "*len(prefix))
                    print_infos += '\n'
                    print_infos += f"Taille de la clé : {key_param}\n"
                    print_infos += f"Format d'affichage : {print_format}\n"
                    print_infos += f"Message : {message}\n"
                
                    print_key = ""
                    for k, v in keys_elements.items():
                        print_key += k.upper()
                        print_key += "\n"
                        if isinstance(v, dict):
                            for kk, vv in v.items():
                                print_key += kk+" : "
                                print_key +='\n'
                                if ticket:
                                    print_key += textwrap.fill(ui.format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_key += textwrap.fill(ui.format_output(vv, print_format), max_width)
                                print_key += "\n"
                        else:
                            if ticket:
                                print_key += textwrap.fill(ui.format_output(v, print_format).replace(' ', ''), max_width)
                                print_key += "\n"
                            else:
                                print_key += textwrap.fill(ui.format_output(v, print_format), max_width)
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
                                    print_res += textwrap.fill(ui.format_output(vv, print_format).replace(' ', ''), max_width)
                                else:
                                    print_res += textwrap.fill(ui.format_output(vv, print_format), max_width)
                                print_res += "\n"
                        else:
                            if ticket:
                                print_res += textwrap.fill(ui.format_output(v, print_format).replace(' ', ''), max_width)
                                print_res += "\n"
                            else:
                                print_res += textwrap.fill(ui.format_output(v, print_format), max_width)
                                print_res += "\n"
                            print_res += "\n"
                        print_res += "\n"
                    return print_infos, print_res, print_key
                
                def gen_energy_footprint(algo_name, key_param, max_width):
                    tkg, wkg, ckg = get_estimate(perfs[algo_name][key_param]['keygen']['time'])
                    tke, wke, cke = get_estimate(perfs[algo_name][key_param]['encrypt']['time'])
                    t = tkg+tke
                    w = wkg + wke
                    c = ckg + cke
                    if max_width == PRINTER_WIDTH:
                        t_str = f"{t:.12f}"
                        execution_time = f"{'Temps de calcul (s)':<{PRINTER_WIDTH-len(t_str)}}{t_str}\n"
                        energy = "Cout energetique \n"
                        w_str = f"{w:.12f}"
                        c_str = f"{c:.12f}"
                        energy += f"   {'Watt':<{PRINTER_WIDTH-(len(c_str)+3)}}{w_str}\n"
                        energy += f"   {'gCO2':<{PRINTER_WIDTH-(len(c_str)+3)}}{c_str}\n"
                    else:
                        execution_time = f"Temps de calcul  : {t:.12f} s\n"
                        energy = f"Cout energetique : {w:.12f} W  {c:.12f} gCO2\n"
                    return execution_time + energy
                
                print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, MINITEL_SCREEN_WHIDTH, res)
                
                energy_footprint = gen_energy_footprint(algo_name, key_param, MINITEL_SCREEN_WHIDTH)
                to_print = ui.display_result(print_infos, print_res, print_key, energy_footprint)
                if to_print == "o":
                    print_infos, print_res, print_key = gen_results(message, algo_name, algo_description, key_param, print_format, PRINTER_WIDTH, res, True)
                    energy_footprint = gen_energy_footprint(algo_name, key_param, PRINTER_WIDTH)
                    print_ticket(PRINTER,print_infos, print_res, print_key, energy_footprint)
                    
                    # t = print_ticket_(PRINTER, print_infos, print_res, print_key, energy_footprint)
                    # print(t)
                ui.print("Appuyez sur entree pour conitnuer ...")
                input()
            

if __name__ == "__main__":
    run()