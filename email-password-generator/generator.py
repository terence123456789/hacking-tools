import random
import json
import string
import os

chars = string.ascii_letters + "!@#$%^&*(),./?><:;'\"" + string.digits
random.seed = (os.urandom(1024))
domain = ['@yahoo.com', '@hotmail.com', '@live.com', '@aol.com', '@gmail.com', '@outlook.com']
names = json.loads(open('names.json', 'r').read()) # decode the json file, then read the file which contains 1 list

def generate_email():
    name_extra = ''.join(random.choice(string.digits) for i in range(3))
    email = random.choice(names) + name_extra + random.choice(domain)
    return email


def generate_password():
    password = ''.join(random.choice(chars) for i in range(12))

    return password

print(generate_email())
print(generate_password())