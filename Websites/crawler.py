import requests
import re
import urllib.parse as urlparse


filtered_links = []
base_url = "https://www.facebook.com/"


def request(url):

    try:
        get_response = requests.get(url)
        return get_response

    except: # url doesn't exist
        return 0


def get_subdomains(base_domain, subdomain_file):

    wordlist_file = open(subdomain_file, "r") # contains a list of possible sub-domains

    for line in wordlist_file:
        test_url = line.strip() + "." + base_domain  # the whole sub-domain + base domain
        result = request(test_url)

        if result:  # sub-domain exists
            print("[+] Discovered sub-domain --> " + test_url)

    wordlist_file.close()


def get_directories(base_domain, directories_file):

    wordlist_file = open(directories_file, "r") # contains a list of possible sub-directories

    for line in wordlist_file:
        test_url =  base_domain + "/" + line.strip()  # the whole base domain + directory
        result = request(test_url)

        if result:  # directory exists
            print("[+] Discovered url --> " + test_url)

    wordlist_file.close()


# discover all links on the current page
def get_links(url):

    if request(url) != 0:  # url is valid

        # extract the links from the url. A list is returned
        href_links = re.findall('(?:href=")(.*?)"', request(url).text)

        for link in href_links:

            link = urlparse.urljoin(url, link)  # join the relative url (/faq) with the base url

            if "#" in link: # urls with # in them are going to point to the same page. so get only one of it
                link = link.split("#")[0]

            # filter out all urls not related to the base and remove repeated links
            if base_url in link and link not in filtered_links:
                filtered_links.append(link)
                print(link)


# recursively discover all links related to the website
def crawl(url):

    if request(url) != 0: # url is valid

        # extract the links. A list is returned
        href_links = re.findall('(?:href=")(.*?)"', request(url).text)

        for link in href_links:

            link = urlparse.urljoin(url, link)  # join the relative url (/faq) with the base url

            if "#" in link:  # urls with # in them are going to point to the same page. so get only one of it
                link = link.split("#")[0]

            # filter out all urls not related to the base and remove repeated links
            if base_url in link and link not in filtered_links:
                filtered_links.append(link)
                print(link)
                crawl(link)  # recursively call crawl to discover all links on the whole website


crawl(base_url)
#get_links("https://www.gv.com.sg/GVHome/")


# get_subdomains("", "subdomains-wordlist-small.txt")
# get_directories("", "files-and-dirs-wordlist.txt")


