import subprocess
import argparse
import re


def get_argument():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface", dest="interface", help="Specify the Interface to change MAC address")
    parser.add_argument("-m","--mac", dest="new_mac", help="Specify the new MAC address")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface, use --help for more info.")

    elif not options.new_mac:
        parser.error("[-] Please specify a new mac, use --help for more info.")

    else:
        return options


def change_mac(interface, new_mac):

    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    ifconfig_result = ifconfig_result.decode('utf-8')

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

    print("[+] Changing MAC address for " + interface + " to " + new_mac)


def get_current_mac(interface):

    try:
        ifconfig_result = subprocess.check_output(["ifconfig", interface])
        ifconfig_result = ifconfig_result.decode('utf-8')

    except:
        return 0

    else:
        mac_address_search_result = re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)

        if mac_address_search_result:
            return mac_address_search_result.group(0)
        else:
            return 0


options = get_argument()

interface = options.interface
new_mac = options.new_mac

current_mac = get_current_mac(interface)

if current_mac != 0:
    print("Current MAC address: " + current_mac)

else:
    print("[-] Could not read MAC address. Please enter a valid interface")
    quit()

change_mac(interface, new_mac)

if get_current_mac(interface) == new_mac:
    print("[+] MAC address was successfully changed to " + new_mac)
else:
    print("[-] MAC address did not get changed.")
