import requests


r = requests.post('https://172.18.0.1:443/.well-known/est/arburg/opcua-client/simpleenroll/', data={'key': 'value'}, verify=False)
print(r)