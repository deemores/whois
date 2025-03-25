import itertools
import string
import sys
import time
import whois
import logging

# Konfiguration
TLD = ".be"
MIN_LENGTH = 2
MAX_LENGTH = 3
RESULT_FILE = "c:\\whois\\whoisresult.txt"
MUST_INCLUDE_SEQUENCE = ""  # Beliebige Zeichenfolge, die im Domainnamen enthalten sein muss
WAIT_SECONDS = 3
MAX_RETRIES = 5  # Maximale Anzahl der Wiederholungsversuche

# Logging-Konfiguration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Enable ANSI escape sequences on Windows
try:
    import ctypes
    kernel32 = ctypes.windll.kernel32
    kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
except ImportError:
    pass  # Nicht-Windows-Systeme benötigen dies nicht

def is_valid_domain_part(part):
    """Prüft, ob ein Domain-Teil gültig ist."""
    if part.startswith("-") or part.endswith("-"):
        return False
    if len(part) >= 4 and part[2:4] == "--":
        return False
    return True

def generate_domains(characters, min_length, max_length, must_include_sequence):
    """Generiert eine Menge von Domainnamen."""
    domains_to_check = set()
    for r in range(min_length, max_length + 1):
        for name_parts in itertools.product(characters, repeat=r):
            url_part = "".join(name_parts)
            if must_include_sequence and must_include_sequence not in url_part:
                continue
            if not is_valid_domain_part(url_part):
                continue
            domains_to_check.add(url_part + TLD)
    return domains_to_check

def check_domain(url, log_file):
    """Prüft, ob eine Domain existiert und schreibt das Ergebnis in die Log-Datei."""
    retries = 0
    wait_seconds = WAIT_SECONDS
    while retries < MAX_RETRIES:
        try:
            #logging.info(f"Checking {url} ...")
            res = whois.whois(url)
            if res.status is not None:
                logging.info(f"{url} exists!")
                return  # Domain existiert, Funktion beenden
            else:
                logging.warning(f"Rate limit reached for {url}. Retrying in {wait_seconds} seconds.")
                time.sleep(wait_seconds)
                wait_seconds *= 2  # Exponentielles Backoff
                retries += 1
        except whois.parser.PywhoisError:
            logging.info(f"{url} is likely unregistered.")
            print(url, file=log_file)
            return  # Unregistriert, Funktion beenden
        except Exception as e:
            logging.error(f"An unexpected error occurred for {url}: {e}")
            retries +=1
            time.sleep(wait_seconds)
            wait_seconds *= 2
    logging.error(f"Max retries reached for {url}. Skipping.")
def main():
    characters = list(string.ascii_lowercase)
    # characters.extend(list(string.digits))
    # characters.append("-")

    if MUST_INCLUDE_SEQUENCE:
        characters.append(MUST_INCLUDE_SEQUENCE)

    domains_to_check = generate_domains(characters, MIN_LENGTH, MAX_LENGTH, MUST_INCLUDE_SEQUENCE)

    with open(RESULT_FILE, "w", encoding="utf-8") as log_file:
        for url in sorted(domains_to_check):
            check_domain(url, log_file)

if __name__ == "__main__":
    main()