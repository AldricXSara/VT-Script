import configparser
import os

relative_path = 'config/'

def writeNewConfig(filepath):
    config = configparser.ConfigParser()
    config.add_section('Identity')
    config.set('Identity', 'API_Key', '')

    config.add_section('API_Allowance')
    config.set('API_Allowance', 'm_used', '')
    config.set('API_Allowance', 'm_allowed', '')
    config.set('API_Allowance', 'd_used', '')
    config.set('API_Allowance', 'd_allowed', '')
    config.set('API_Allowance', 'h_used', '')
    config.set('API_Allowance', 'h_allowed', '')

    filename = os.path.join(filepath, '..', '..', '..', relative_path) + 'config.ini'

    try:
        with open(filename, 'w') as configfile:
            config.write(configfile)
    except FileNotFoundError:
        os.makedirs(os.path.join(filepath, '..', '..', '..', relative_path))
        with open(filename, 'w') as configfile:
            config.write(configfile)

def updateConfig(filepath, cSection, cLabel, cValue):
    config = configparser.ConfigParser()
    filename = os.path.join(filepath, '..', '..', '..', relative_path) + 'config.ini'
    config.read(filename)
    config.set(cSection, cLabel, cValue)

    with open(filename, 'w') as configfile:
        config.write(configfile)


def readconfig(filepath):
    config = configparser.ConfigParser()
    filename = os.path.join(filepath, '..', '..', '..', relative_path) + 'config.ini'
    config.read(filename)

    return config.get('Identity', 'API_KEY')

