import requests

url = "https://diskominfo.acehprov.go.id"

headers = {
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
    "x-apikey":"d8860ddc0dc6054aa98e324a3881ee5ff2a87efd9ff7d7e6978c3ecf35786308",
    
}

response = requests.post(url, headers=headers)

print(response.text)
