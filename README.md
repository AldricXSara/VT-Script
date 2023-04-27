# VT-Script
VT Script is a project that utilizes Virustotal API to do bulk IOC reputation lookups and hash conversions.
The project's goal is to speed up the rate at which users will look up IOCs against Virustotal's knowledge based compared to manual searching using Virustotal's GUI.

Please note that this is not a professional/enterprise application and is meant to be an "automation" aid and as the developer's practice in using VT's API.

## Dependencies

### Python 3
-instal Python 3 (3.11) from `https://www.python.org`

The following are the Python dependencies for this project:

-`PySimpleGui` for Tinker UI elements

     pip install pysimplegui
     
-`Validators` for input validation

     pip install validators
     
-`Requests` to manage http request datatype

     pip install requests
