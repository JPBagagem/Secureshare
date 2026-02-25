import requests
import os

requests_ = requests.Session()
requests_.verify = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Api", "certs", "local.crt")
