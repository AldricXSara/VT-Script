import requests
from charset_normalizer import md__mypyc


def get_allowance(apikey):
    url = "https://www.virustotal.com/api/v3/users/" + apikey + "/overall_quotas"

    headers = {
        "Accept": "application/json",
        "x-apikey": apikey
    }
    allowance = []
    try:
        response = requests.get(url, headers=headers)
        print(response.json())
        info = response.json()
        monthly = [info['data']['api_requests_monthly']['user']['used'],
                   info['data']['api_requests_monthly']['user']['allowed']]
        daily = [info['data']['api_requests_daily']['user']['used'],
                 info['data']['api_requests_daily']['user']['allowed']]
        hourly = [info['data']['api_requests_hourly']['user']['used'],
                  info['data']['api_requests_hourly']['user']['allowed']]
        allowance.append(monthly)
        allowance.append(daily)
        allowance.append(hourly)
        print(allowance)
    finally:
        print("Connection failed")
        monthly = 0
        daily = 0
        hourly = 0
        allowance.append(monthly)
        allowance.append(daily)
        allowance.append(hourly)

    return allowance
