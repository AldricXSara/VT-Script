import ipaddress
import validators
from urllib.parse import urlparse
import re

def validate_ip(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        print("Not an IP. Skipping")
        return False


def validate_hash(hashinput):
    md5pattern = re.compile("^[a-fA-F0-9]{32}$")
    sha1pattern = re.compile("^[a-fA-F0-9]{40}$")
    sha256pattern = re.compile("^[a-fA-F0-9]{64}$")

    if md5pattern.match(hashinput):
        return "MD5"
    elif sha1pattern.match(hashinput):
        return "SHA1"
    elif sha256pattern.match(hashinput):
        return "SHA256"
    else:
        return False


def validate_domain(urlinput):
    domainRegex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" +"+[A-Za-z]{2,6}"
    p = re.compile(domainRegex)
    try:
        result = urlparse(urlinput)
        if result.scheme and result.netloc:
            return "URL"
        else:
            if(re.search(p, urlinput)):
                return "Domain"
            else:
                return False
    except ValueError:
        print("Not a Domain.")
        return False
