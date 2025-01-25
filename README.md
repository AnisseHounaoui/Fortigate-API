# Fortigate-API

This is a python project using mainly requests library to interact with multiple Fortigates REST APIs.

Features:

✅ Manage MFA authentication (username + password + fortitoken)

✅ Store cookies for all fortigate portals in pkl files and ensuring sessions are well-handled
  
✅ Get multiple fortigate configs (IPS profiles, SSL-VPN config...)
  
🔄 Verify if every fortigate is compliant to specific config

✅ Handle exceptions to minimize login failures to the portals

🔄 Create a GUI using tkinter to display config for all fortigates

---
## Installation:

```
python3 -m pip install -r requirements.txt
```
## Usage:


Modify config.json file:

```
{
  "username": "xxx",
  "password": "xxx",
  "fg_url": "Fortigate_URL"
}
```

Run python script (Implement arguments in future) and enter fortitoken:
```
python.exe fortigapi.py
```


