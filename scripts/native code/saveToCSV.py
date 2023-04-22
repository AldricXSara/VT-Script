import csv
from datetime import datetime
import os

relative_path = 'output/'

def writeToCSV(filepath, headers, rowValues, operation):
    current_time = datetime.now().strftime("%m%d%Y-%H%M%S")
    filename = os.path.join(filepath, '..', '..', '..', relative_path) + current_time + ' ' + operation + ' Results.csv'
    try:
        with open(filename, 'w', newline='') as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL)
            w.writerow(headers)
            for i in rowValues:
              w.writerow(i)
    except FileNotFoundError:
        os.makedirs(os.path.join(filepath, '..', '..', '..', relative_path))
        with open(filename, 'w', newline='') as f:
            w = csv.writer(f, quoting=csv.QUOTE_ALL)
            w.writerow(headers)
            for i in rowValues:
              w.writerow(i)

def getMal(rowValues):
    newout = []

    for i in rowValues:
        if int(i[5]) > 0:
            newout.append(i)

    return newout
