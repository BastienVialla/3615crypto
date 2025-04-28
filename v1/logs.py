import os
from datetime import datetime

from config import *

DEFAULT_COUNTERS = (0, 0)

def read_counters(filename):
    """
    Reads the two counter values from a file.
    Returns a tuple (counter1, counter2).
    Returns DEFAULT_COUNTERS if the file doesn't exist, is empty, or has an invalid format.
    """
    if not os.path.exists(filename):
        print(f"Counter file '{filename}' not found. Starting counters from {DEFAULT_COUNTERS}.")
        return DEFAULT_COUNTERS

    try:
        with open(filename, 'r') as f:
            content = f.read().strip()
            if not content: # Handle empty file case
                 print(f"Counter file '{filename}' is empty. Starting counters from {DEFAULT_COUNTERS}.")
                 return DEFAULT_COUNTERS

            # Split the content by comma
            parts = content.split(',')

            # Ensure we got exactly two parts
            if len(parts) != 2:
                print(f"Invalid format in '{filename}'. Expected 2 comma-separated numbers, got '{content}'. Starting from {DEFAULT_COUNTERS}.")
                return DEFAULT_COUNTERS

            # Attempt to convert parts to integers
            counter1 = int(parts[0].strip()) # Use strip() in case there's whitespace around the numbers
            counter2 = int(parts[1].strip())

            return (counter1, counter2) # Return values as a tuple

    except ValueError:
        # Handle cases where the parts cannot be converted to integers
        print(f"Could not convert parts to integers from '{filename}'. Content was '{content}'. Starting from {DEFAULT_COUNTERS}.")
        return DEFAULT_COUNTERS
    except Exception as e:
        # Catch other potential file reading errors
        print(f"An error occurred while reading '{filename}': {e}. Starting counters from {DEFAULT_COUNTERS}.")
        return DEFAULT_COUNTERS
    
def write_counters(filename, value1, value2):
    """Writes the two current counter values to a file, comma-separated."""
    try:
        with open(filename, 'w') as f:
            f.write(f"{value1},{value2}") # Write values separated by a comma
        # print(f"Counter values ({value1}, {value2}) saved to '{filename}'.") # Optional confirmation
    except Exception as e:
        print(f"An error occurred while writing to '{filename}': {e}")
        
def get_daily_log_filepath():
    """
    Generates the full path for today's log file based on the current date.
    Ensures the log directory exists.
    """
    # Get the current date
    today = datetime.now()

    # Format the date for the filename
    date_str = today.strftime("%Y-%m-%d") # e.g., "2023-10-27"
    filename = f"{date_str}.log" # e.g., "app_2023-10-27.log"

    # Combine directory and filename
    log_filepath = os.path.join(LOG_DIR, filename)

    # Create the log directory if it doesn't exist
    # exist_ok=True prevents an error if the directory already exists
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError as e:
        print(f"Error creating log directory '{LOG_DIR}': {e}")
        # Fallback: Log to the current directory if directory creation fails
        print(f"WARNING: Logging to current directory instead of '{LOG_DIR}'.")
        log_filepath = filename # Use just the filename in the current directory

    return log_filepath

def write_log(message):
    """
    Writes a timestamped message to today's log file.
    Creates a new file each day automatically.
    """
    log_filepath = get_daily_log_filepath() # Get the correct file path for today

    # Get the current timestamp for the log entry
    now = datetime.now()
    timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S") # e.g., "2023-10-27 10:30:00"

    # Format the complete log line
    log_entry = f"{timestamp_str},{message}\n"

    # Open the log file in append mode ('a') and write the entry
    # 'a' mode creates the file if it doesn't exist or appends if it does.
    # encoding='utf-8' is recommended for wider character support.
    try:
        with open(log_filepath, 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        # If writing fails, print to the console as a fallback/error
        print(f"FATAL ERROR: Could not write to log file '{log_filepath}'. Message: '{message}'. Error: {e}")