import configparser
import os
import configfile
import index
import tableoutput
import validation
import api_allowance_query as allowance
import lookup
import PySimpleGUI as sg
import re
import saveToCSV

filepath = os.path.dirname(__file__)

# def parseChunkbox(values):
    # comment

window = index.create_index_window()
outList = []
eventCounter = 0

try:
    configfile.readconfig(filepath)
except configparser.NoSectionError as e:
    configfile.writeNewConfig(filepath)

#apikey = configfile.readconfig()
#print(apikey)
while True:
    outList = []
    eventCounter = 0
    window.refresh()
    event, values = window.read()
    apikey = values["-APIKEY-"]
    lookupResult = []
    apiAllowance = []
    if event == sg.WIN_CLOSED or event == 'Exit':  # if user closes window or clicks Exit
        break
    if event == '-API-':
        if apikey == '':
            sg.popup_ok("Please enter an API Key")
        else:
            apiAllowance = allowance.get_allowance(apikey)
            sg.popup_ok("Monthly: " + str(apiAllowance[0][0]) + "/" + str(apiAllowance[0][1]) + "\n" +
                        "Daily: " + str(apiAllowance[1][0]) + "/" + str(apiAllowance[1][1]) + "\n" +
                        "Hourly: " + str(apiAllowance[2][0]) + "/" + str(apiAllowance[2][1]) + "\n",
                        title="Allowance Info")
    if event == '-SAVEAPI-':
        if apikey == '':
            sg.popup_ok("Please enter an API Key")
        else:
            apiAllowance = allowance.get_allowance(apikey)
            configfile.updateConfig(filepath, 'Identity', 'API_Key', apikey)
            configfile.updateConfig(filepath, 'API_Allowance', 'm_used', str(apiAllowance[0][0]))
            configfile.updateConfig(filepath, 'API_Allowance', 'm_allowed', str(apiAllowance[0][1]))
            configfile.updateConfig(filepath, 'API_Allowance', 'd_used', str(apiAllowance[1][0]))
            configfile.updateConfig(filepath, 'API_Allowance', 'd_allowed', str(apiAllowance[1][1]))
            configfile.updateConfig(filepath, 'API_Allowance', 'h_used', str(apiAllowance[2][0]))
            configfile.updateConfig(filepath, 'API_Allowance', 'h_allowed', str(apiAllowance[2][1]))
    if event == '-LOADAPI-':
        apikey = configfile.readconfig(filepath)
        if apikey == '':
            sg.popup_ok("No API Key found in Config")
        else:
            sg.popup_ok("API Key loaded from config data")
            window['-APIKEY-'].update(value=apikey)
    if event == '-MD5-':
        if apikey == '':
            sg.popup_ok("Please enter an API Key")
        elif values['-chunkbox-'] == '':
            sg.popup_ok("The entry field is empty", title="Empty field detected")
        else:
            outText = values['-chunkbox-']
            input_list = re.split(r'[\n \r]', outText)
            input_list = list(filter(None, input_list))
            print(input_list)
            eventCounter = 0
            for i in input_list:
                print(i)
                if validation.validate_hash(i.strip()):
                    datatype = validation.validate_hash(i.strip())
                    lookupResult = lookup.convertHash(i.strip(), apikey, datatype, "MD5")
                    if len(lookupResult) > 0:
                        outList.append(lookupResult)
                    eventCounter += 1
                    window['-progress-'].update(value="Converting: " + str(eventCounter) + "/" + str(len(input_list)))
                    window.refresh()
            if len(outList) > 0:
                headers = ["Input", "Input type", "Output", "Output Type"]
                saveToCSV.writeToCSV(headers,outList, 'Conversion')
    if event == '-SHA256-':
        if apikey == '':
            sg.popup_ok("Please enter an API Key")
        elif values['-chunkbox-'] == '':
            sg.popup_ok("The entry field is empty", title="Empty field detected")
        else:
            eventCounter = 0
            outText = values['-chunkbox-']
            input_list = re.split(r'[\n \r]', outText)
            input_list = list(filter(None, input_list))
            print(input_list)
            for i in input_list:
                print(i)
                if validation.validate_hash(i.strip()):
                    datatype = validation.validate_hash(i.strip())
                    lookupResult = lookup.convertHash(i.strip(), apikey, datatype, "SHA256")
                    if len(lookupResult) > 0:
                        outList.append(lookupResult)
                    eventCounter += 1
                    window['-progress-'].update(value="Converting: " + str(eventCounter) + "/" + str(len(input_list)))
                    window.refresh()
            if len(outList) > 0:
                headers = ["Input", "Input type", "Output", "Output Type"]
                saveToCSV.writeToCSV(headers,outList, 'Conversion')
    if event == "IOC Lookup":
        if apikey == '':
            sg.popup_ok("Please enter an API Key")
        elif values['-chunkbox-'] == '':
            sg.popup_ok("The entry field is empty", title="Empty field detected")
        else:
            #print(apikey)
            outText = values['-chunkbox-']
            #input_list = outText.split("\n")
            input_list = re.split(r'[\n \r]', outText)
            input_list = list(filter(None, input_list))
            for i in input_list:
                eventCounter += 1
                #IP Address checking and lookup
                if validation.validate_ip(i.strip()):
                    lookupResult = lookup.IP_lookup(i.strip(), apikey)
                    print(lookupResult)
                    if len(lookupResult) > 0:
                        outList.append(lookupResult)
                    #allowance.get_allowance(apikey)
                    print(outList)
                elif validation.validate_hash(i.strip()):
                    datatype = validation.validate_hash(i.strip())
                    lookupResult = lookup.hash_lookup(i.strip(), apikey, datatype)
                    if len(lookupResult) > 0:
                        outList.append(lookupResult)
                    print(outList)
                elif validation.validate_domain(i.strip()) == 'Domain':
                    lookupResult = lookup.domain_lookup(i.strip(), apikey)
                    print(lookupResult)
                    if len(lookupResult) > 0:
                        outList.append(lookupResult)
                    print(outList)
                #URL checking and lookup
                elif validation.validate_domain(i.strip()) == 'URL':
                    lookupResult = lookup.URL_lookup(i.strip(), apikey)
                    print(lookupResult)
                    if len(lookupResult) > 0:
                        outList.append(lookupResult)
                    print(outList)
                window['-progress-'].update(value="Looking up: " + str(eventCounter)+"/" + str(len(input_list)))
                window.refresh()
            #open the table window with the output of the lookup
            tableView = tableoutput.tableGen(outList)
            while True:
                tEvent, tValues = tableView.read()
                tableView.refresh()
                if tEvent == sg.WIN_CLOSED or tEvent == 'Exit':  # if user closes window or clicks cancel
                    break
                if tEvent == '-CSV-':
                    headers = ["IOC", "Data type", "Owner", "Country", "Harmless", "Malicious",
                               "Suspicious", "Undetected", "Reputation Score"]
                    saveToCSV.writeToCSV(filepath, headers, outList, 'Lookup')
                    flag = 1
                if tEvent == '-MAL-':
                    malList = []
                    headers = ["IOC", "Data type", "Owner", "Country", "Harmless", "Malicious",
                               "Suspicious", "Undetected", "Reputation Score"]
                    malList = saveToCSV.getMal(outList)
                    saveToCSV.writeToCSV(filepath, headers, malList, 'Malicious')
                    flag = 1
            tableView.close()
window.close()
