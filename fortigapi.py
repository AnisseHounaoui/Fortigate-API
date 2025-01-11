import requests
import os
import pickle
import json


def load_config():
    if os.path.exists("config.json"):
        with open("config.json", "r") as file:
            config = json.load(file)
        return config
    else:
        print("config file not found")

def save_cookies(session,cookie_file):
    with open(cookie_file, 'wb') as f:
        pickle.dump(session.cookies, f)
    print(f"Cookies saved to {cookie_file}")

def load_cookies(session, cookie_file, fg_url):
    if os.path.exists(cookie_file):
        with open(cookie_file, 'rb') as f:
            # case 1 : cookies exists and expired or doesnt exists in file -> test url and results doesnt exists -> return None (to initial new login for new cookies in logincheck)
            # case 2: cookies exists and valid -> test  url and verify that results exists -> return session.cookies
            cookies = pickle.load(f)
            f.close()
        # verify that cookies exists and valid with test GET
        test_url = fg_url + "/api/v2/monitor/system/ha-checksums?vdom=root"
        headers = {
            'Content-Type': 'application/json'
        }
        session.cookies.update(cookies)
        response = requests.get(test_url, headers=headers, cookies=session.cookies, verify=False)
        try:
            print(f"test response: {response.json()}")
            if response.json():  # verifying that response content is returned = cookies are valid

                return session.cookies
            else:
                print("No results found in response.")
                return None
        except requests.exceptions.JSONDecodeError:
            print(f"Error decoding JSON response from {test_url}: {response.text}")
            return None
    else:
        return None



def logincheck(config):

    fg_url = config["fg_url55"]
    fg_url_login = fg_url + "/logincheck"
    session = requests.session()

    cookie_file = f"{fg_url.split('//')[1].split(':')[0]}_cookies.pkl"
    cookies = load_cookies(session, cookie_file, fg_url)

    print(f"Cookies loaded: {cookies}")

    # Invalid or missing (if first time) cookies, initial login
    if cookies is None:
        print("Missing cookies, initiating login...")
        payload = {
            'username': config["username"],
            'secretkey': config["password"],
            'ajax': 1
        }
        headers = {
            'Content-Type': 'application/json'
        }

        response1 = session.post(fg_url_login, headers=headers, data=payload, verify=False)
        session.cookies.update(response1.cookies)
        fortitoken = int(input("Enter fortitoken:"))
        payload["token_code"] = fortitoken
        response2 = session.post(fg_url_login, headers=headers, cookies=session.cookies, data=payload, verify=False)

        if response2.status_code == 200:
            save_cookies(session, cookie_file)
        else:
            print(f"connection not established: {response2.status_code}")
    else:
        session.cookies = cookies

    print(f"Final cookies: {session.cookies}")
    return session.cookies

# FG version
def get_info(fg_url, cookies):
    ha_url = fg_url + "/api/v2/monitor/system/firmware?vdom=root"

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", ha_url, headers=headers, cookies=cookies, verify=False)

    #name = response.json()['results']
    serial_num = response.json()['serial']
    version = response.json()['version']
    build = response.json()['build']

    print(f"\nDevice infos: {fg_url}")
    print(f"\nSerial Number: {serial_num}")
    print(f"\nVersion: {version} build {build}")

# Fetch SSL-VPN settings
def get_ssl_vpn(fg_url, cookies):
    ha_url = fg_url + "/api/v2/cmdb/vpn.ssl/settings?datasource=1&vdom=root&with_meta=1"

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", ha_url, headers=headers, cookies=cookies, verify=False)
    allowed_hosts = response.json()["results"]["source-address"]
    #if allowed_hosts[0]['name'] == "all":

    allowed_dict = {"Allowed groups": []}
    for i in range(len(allowed_hosts)):
        allowed_dict["Allowed groups"].append(allowed_hosts[i]["name"])
    print(f"\nAccess allowed to :{allowed_dict}")
# Fetch HA status
def checksum_compare(result):
    checksum_primary = result[0]["checksum"]["all"]
    checksum_secondary = result[1]["checksum"]["all"]
    return checksum_primary == checksum_secondary
def get_ha(fg_url, cookies):
    ha_url = fg_url + "/api/v2/monitor/system/ha-checksums?vdom=root"

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", ha_url, headers=headers, cookies=cookies, verify=False)
    results = response.json()['results']
    if results:
        if checksum_compare(results):
            print("Fortigates are Synchronized")
        else:
            print("Fortigates are NOT Synchronized")
    else:
        print("HA config not found")

def get_config(config):
    fg_cookies = logincheck(config)
    fg_url = config["fg_url55"]
    print(f"\nFetching configuration for {fg_url}")
    get_info(fg_url,fg_cookies)
    get_ha(fg_url,fg_cookies)
    get_ssl_vpn(fg_url, fg_cookies)


def main():

    config = load_config()
    #fg_url  = config["fg_url"]
    #fortitoken = int(input("Enter fortitoken:"))

    get_config(config)

if __name__ == '__main__':
    main()