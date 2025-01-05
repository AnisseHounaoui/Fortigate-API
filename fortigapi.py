import requests
import json


def load_config():
    with open("config.json", "r") as file:
        config = json.load(file)
    return config


def logincheck(fortitoken):
    config = load_config()

    fg_url = config["fg_url"] + "/logincheck"
    payload = {
        'username': config["username"],
        'secretkey': config["password"],
        'ajax': 1
    }
    headers = {
        'Content-Type': 'application/json'
    }

    session = requests.session()


    response1 = session.post(fg_url, headers=headers, data=payload, verify=False)

    session.cookies.update(response1.cookies)

    payload["token_code"] = fortitoken

    response2 = session.post(fg_url, headers=headers, cookies=session.cookies, data=payload, verify=False)


    print(session.cookies)

def main():

    fortitoken = int(input("Enter fortitoken:"))

    print(logincheck(fortitoken))

if __name__ == '__main__':
    main()