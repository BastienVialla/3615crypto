from datetime import datetime
from time import sleep
import random

from logos import LOGO_HEADER_PRINTER

PRINTER_WIDTH = 48

def ticket_seperator():
    return '-'*PRINTER_WIDTH

def print_ticket(printer, infos, res, keys = None):
    current_datetime = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    printer.set(align='left', font='a', width=1, height=1)
    printer.text('\n')
    printer.text('\n')
    printer.text('\n')
    sleep(.5)
    printer.text(LOGO_HEADER_PRINTER)
    printer.text('\n\n')
    printer.text(infos)
    printer.text('\n')
    if keys is not None:
        printer.text(keys)
        printer.text('\n')
    printer.text(res)
    printer.text('\n')
    printer.text(ticket_seperator())
    printer.text('\n')
    n = LOGO_HEADER_PRINTER.count('\n')
    n += infos.count('\n')
    if keys:
        n += keys.count('\n')
    n += res.count('\n')
    n += 9
    c = random.uniform(0, 1) + n*0.1
    cout = f"Prix : {c:.2f} Fr"
    end_line = f"{current_datetime:<{48 - len(str(cout))}}{cout}"
    printer.text(end_line)
    printer.text('\n')
    
def print_ticket_(infos, res, keys = None):
    current_datetime = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    ticket = ""
    ticket = "\n\n\n"
    ticket += LOGO_HEADER_PRINTER
    ticket += '\n\n'
    ticket += infos
    ticket += '\n'
    if keys is not None:
        ticket += keys
        ticket += '\n'
    ticket += res
    ticket += '\n'
    ticket += ticket_seperator()
    ticket += '\n'
    c = random.uniform(0, 1) + ticket.count('\n')*0.1
    cout = f"Prix : {c:.2f} Fr"
    end_line = f"{current_datetime:<{48 - len(str(cout))}}{cout}"
    ticket += end_line
    ticket += '\n'
    return ticket