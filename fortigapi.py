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
            cookies = pickle.load(f)

        #verify that cookies exists and valid with test GET
        test_url = fg_url + "/api/v2/monitor/system/ha-checksums?vdom=root"
        headers = {
            'Content-Type': 'application/json'
        }
        session.cookies.update(cookies)
        response = requests.request("GET", test_url, headers=headers, cookies=session.cookies, verify=False)

        print(f"test response: {response.json()['results']}")
        if response.json()['results']: #verifying that response content is returned = cookies are valid
            return session.cookies
        return None


def logincheck(fortitoken, config):

    fg_url = config["fg_url"]
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
        payload["token_code"] = fortitoken
        response2 = session.post(fg_url_login, headers=headers, cookies=session.cookies, data=payload, verify=False)

        if response2.status_code == 200:
            save_cookies(session, cookie_file)
        else:
            print(f"connection not established: {response2.status_code}")
    else:
        session.cookies = cookies

    print(f"Final cookies: {session.cookies}")
    #return session.cookies

def main():

    config = load_config()
    #fg_url  = config["fg_url"]
    fortitoken = int(input("Enter fortitoken:"))
    print(logincheck(fortitoken,config))

if __name__ == '__main__':
    main()