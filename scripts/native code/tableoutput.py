import PySimpleGUI as sg


def tableGen(output_list):

    toprow = ["IOC", "Data type", "Owner", "Country", "Harmless", "Malicious", "Suspicious", "Undetected", "Reputation Score"]
    rows = output_list

    table1 = sg.Table(values= rows, headings= toprow,
                      auto_size_columns=True,
                      display_row_numbers=True,
                      key='-TABLE-',
                      selected_row_colors='blue on white',
                      enable_events=True,
                      expand_x=True,
                      expand_y=True,
                      enable_click_events=True)

    layout = [[table1],
              [sg.Button("Export ALL to CSV", key='-CSV-'), sg.Button("Export MAL to CSV", key='-MAL-')],
              [sg.Exit()]
            ]

    return sg.Window("Lookup Results", layout)