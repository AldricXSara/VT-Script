import base64


def urlencode(urlinput):
    return base64.urlsafe_b64encode(urlinput.encode()).decode().strip("=")
