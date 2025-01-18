import requests
import os
import pickle
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        test_url = fg_url + "/api/v2/cmdb/system/vdom"
        headers = {
            'Content-Type': 'application/json'
        }
        session.cookies.update(cookies)
        try:
            response = requests.get(test_url, headers=headers, cookies=session.cookies, verify=False, timeout=5)

            try:
                if response.json():  # verifying that response content is returned = cookies are valid
                    return session.cookies
                else:
                    print("No results found in response.")
                    return None
            except requests.exceptions.JSONDecodeError:
                return None
        except requests.exceptions.Timeout:
            print("The request timed out after 5 seconds.")
    else:
        return None

def logincheck(fg_url,config):

    fg_url_login = fg_url + "/logincheck"
    session = requests.session()

    cookie_file = f"{fg_url.split('//')[1].split(':')[0]}_cookies.pkl"
    cookies = load_cookies(session, cookie_file, fg_url)


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

        while len(session.cookies.get_dict()) != 2:# for fortitoken to be valid session.cookie should contains 2 cookies
            fortitoken = input("Enter fortitoken: ")
            if fortitoken.isdigit() and len(fortitoken) == 6: #validating fortitoken format
                response1 = session.post(fg_url_login, headers=headers, data=payload, verify=False, timeout=5)
                session.cookies.update(response1.cookies)
                #print(session.cookies.get_dict())
                payload["token_code"] = int(fortitoken)
                response2 = session.post(fg_url_login, headers=headers, cookies=session.cookies, data=payload, verify=False, timeout=5)
                if len(session.cookies.get_dict()) == 0: #if second response cookies are empty -> invalid fortitoken value
                    print("Invalid fortitoken value.")
                    payload.pop("token_code")
                    session.cookies.clear()
                elif len(session.cookies.get_dict()) == 2: #if both cookies are present
                    break
            else:
                print("Invalid fortitoken format.")

        save_cookies(session, cookie_file)

    else:
        session.cookies = cookies

    #print(f"Final cookies: {session.cookies}")
    return session.cookies

# FG version
def get_info(fg_url, cookies):
    ha_url = fg_url + "/api/v2/monitor/system/firmware?vdom=root"
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", ha_url, headers=headers, cookies=cookies, verify=False, timeout=5)


    #name = response.json()['results']
    json_resp = response.json()
    serial_num = json_resp.get("serial")
    version = json_resp.get("version")
    build = json_resp.get("build")
    # Only print if values are present
    if serial_num and version and build:
        print(f"\nDevice infos:")
        print(f"Serial Number: {serial_num}")
        print(f"Version: {version} build {build}")
    else:
        pass

# Fetch IPS profiles settings
def get_ips_profiles(fg_url, cookies):
    ips_url = fg_url + "/api/v2/cmdb/ips/sensor?with_meta=1&datasource=1&skip=1&vdom=root"

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", ips_url, headers=headers, cookies=cookies, verify=False, timeout=5)

    ips_profiles = response.json().get('results')
    for i in range(len(ips_profiles)):
        if ips_profiles[i].get('q_ref') is None or ips_profiles[i].get('q_ref') == 0:  #ips applied at least on 1 resource
            #print("IPS profiles config not applied to any ressource")
            pass
        else:
            print("\n" + ips_profiles[i].get('name') + ":")
            for entry in ips_profiles[i].get('entries'):
                if entry.get("location") is None:
                    pass
                else:
                    ips_location = entry.get("location").split()
                    severity = entry.get("severity").split()
                    action = entry.get("action")

                    packet_logging = entry.get("log-packet")
                    print(f"Location: {str(ips_location)}")
                    print(f"Severity: {str(severity)}")
                    print(f"Action: {action}")
                    print(f"Packet logging: {packet_logging}")
                    print("----------------------------")
                    #print(str(ips_location) + " , " + str(severity) + " , " + action + " , "+ packet_logging)


# Fetch SSL-VPN settings
def get_ssl_vpn(fg_url, cookies):
    vpn_url = fg_url + "/api/v2/cmdb/vpn.ssl/settings?datasource=1&vdom=root&with_meta=1"

    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request("GET", vpn_url, headers=headers, cookies=cookies, verify=False, timeout=5)
    allowed_hosts = response.json()["results"].get("source-address")
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
    response = requests.request("GET", ha_url, headers=headers, cookies=cookies, verify=False, timeout=5)
    results = response.json()['results']
    if results:
        if checksum_compare(results):
            print("\nFortigates are Synchronized\n")
        else:
            print("\nFortigates are NOT Synchronized\n")
    else:
        print("HA config not found")

def get_config(fg_url,config):
    fg_cookies = logincheck(fg_url,config)
    print(f"\nFetching configuration for {fg_url}")
    get_info(fg_url,fg_cookies)
    get_ha(fg_url,fg_cookies)
    get_ssl_vpn(fg_url,fg_cookies)
    get_ips_profiles(fg_url,fg_cookies)

def main():

    config = load_config()
    #fg_url  = config["fg_url"]
    #fortitoken = int(input("Enter fortitoken:"))
    fg_url = config["fg_url55"]

    get_config(fg_url,config)

if __name__ == '__main__':
    main()