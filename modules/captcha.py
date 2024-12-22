import toml
import json
import random
import requests
import capsolver
from   time import sleep

with open("config.toml", "r") as f:
    config = toml.load(f)

api_key = config["script"]["api_key"]

with open("proxies.txt", "r") as proxy_file:
    proxies = [line.strip() for line in proxy_file if line.strip()]

def is_valid_proxy(proxy):
    parts = proxy.split(':')
    if len(parts) == 4:
        ip, port, user, password = parts
        if port.isdigit():
            return True
    return False

valid_proxies = [proxy for proxy in proxies if is_valid_proxy(proxy)]

capsolver.api_key = api_key

class Captcha:
    def _solve_captcha(self, blob: str):
        proxy = random.choice(valid_proxies)
        
        solution: dict = capsolver.solve(
            {
                "type": "FunCaptchaTask",
                "websiteURL": "https://www.signu.live.com",
                "websitePublicKey": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                "data": '{"blob": "' + blob + '"}',
                "proxy": proxy,
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
            }
        )
        if token := solution.get("gRecaptchaResponse"):
            return token

        return Captcha._solve_captcha()