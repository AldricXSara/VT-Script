import PySimpleGUI as sg

def create_index_window():
    sg.theme('DarkTeal2')

    layout = [
        [sg.Text('VirusTotal Bulk IOC Checker')],
        [sg.Text("API Key:"), sg.InputText(key="-APIKEY-", password_char='*'),
         sg.Button("Get API Allowance", key="-API-"), sg.Button("Save API Info", key="-SAVEAPI-"),
         sg.Button("Load Config Data", key="-LOADAPI-")],
        [sg.Text('Currently not looking up.', key='-progress-')],
        [sg.Multiline(size=(75,5), key='-chunkbox-')],
        [sg.Button("IOC Lookup"), sg.Button("Md5 Conversion", key='-MD5-'),
         sg.Button("Sha256 Conversion", key='-SHA256-'),
         sg.Button('Exit')]
    ]

    #window = sg.Window('Starting Window', layout)
    #event, values = window.read()
    #window.close()
    return sg.Window('Script goes brr', layout)