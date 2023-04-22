import configparser
import configfile
from pathlib import Path


def check_firstboot():
    config = configparser.ConfigParser()
    if Path('config.ini').is_file():
        config.read("config.ini")
        print("Just opened the old file")
        userinfo = [config.get('Identity', 'API_KEY'),
                    config.get('API_Allowance', 'm_used'),
                    config.get('API_Allowance', 'm_allowed'),
                    config.get('API_Allowance', 'd_used'),
                    config.get('API_Allowance', 'd_allowed'),
                    config.get('API_Allowance', 'h_used'),
                    config.get('API_Allowance', 'h_allowed')]

        return userinfo
    else:
        configfile.writeNewConfig()
        print("Made a new file")
        config.read("config.ini")
        userinfo = [config.get('Identity', 'API_KEY'),
                    config.get('API_Allowance', 'm_used'),
                    config.get('API_Allowance', 'm_allowed'),
                    config.get('API_Allowance', 'd_used'),
                    config.get('API_Allowance', 'd_allowed'),
                    config.get('API_Allowance', 'h_used'),
                    config.get('API_Allowance', 'h_allowed')]
        return userinfo


userInfo = check_firstboot()
print(userInfo)