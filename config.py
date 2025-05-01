import pathlib

HEXA_CHARS = '0123456789abcdef'
MINITEL_SCREEN_WHIDTH = 80

QUIT_STR = ":q:"
SPEED_OPTION_MENU_STR = ":v:"

# Logging
LOG_DIR = "./logs/"
COUNTER_FILE = "./logs/counters.txt"
LOG_MESSAGE_FORMAT = "%Y-%m-%d %H:%M:%S,%s" # Format for each log entry (timestamp + message)

# PRINTER
PRINTER_VENDOR_ID = 0x1fc9
PRINTER_PRODUCT_ID = 0x2016
PRINTER_NAME = 'POS-80'

RSA_CACHE_DIRECTORY = pathlib.Path("./cache/RSA/")
