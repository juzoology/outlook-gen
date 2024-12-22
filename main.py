
import os
import toml
import json
import html
import time
import base64
import requests
from   re                 import findall, search, sub
from   bs4                import BeautifulSoup
from   execjs             import compile as js_compile
from   random             import randint
from   datetime           import datetime, timezone
from   tls_client         import Session
from   urllib.parse       import unquote
from   concurrent.futures import ThreadPoolExecutor, as_completed

from   modules.utils      import Print
from   modules.captcha    import Captcha

with open("config.toml", "r") as f:
    config = toml.load(f)

class Encryptor:
    def __init__(self):
        self._cipher = js_compile(open("cipher_value.js").read())

    def encrypt_value(self, password, num, key) -> str:
        return self._cipher.call("encrypt", password, num, key)

class Utils:
    @staticmethod
    def get_names():    
        response = requests.get("https://randomuser.me/api").json()["results"][0]["name"]
    
        name, last_name = response["first"], response["last"]

        return name, last_name

    @staticmethod
    def decode_url(encoded_url):
        partially_decoded_url = html.unescape(encoded_url)
        decoded_url = unquote(partially_decoded_url)
        decoded_url = sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), decoded_url)
        
        return decoded_url

    @staticmethod
    def ai_session():
        session_id = base64.urlsafe_b64encode(os.urandom(16)).decode("utf-8").rstrip("=")

        timestamp = str(int(time.time() * 1000))

        ai_session = f"{session_id}|{timestamp}|{timestamp}"

        return ai_session

class Outlook:
    def __init__(self) -> None:
        self.session = Session(
            client_identifier = "firefox_121",
            random_tls_extension_order = True
        )
        self.cookies = {}

        self.name, self.lname = Utils.get_names()
        self.email = f"{self.name.lower()}.{self.lname.lower()}{randint(100,999)}@outlook.com"

        Print.inf(f"Starting Register with: {self.email}.")
        
    def getFirstValues(self):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "Host": "signup.live.com",
            "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }
        res = self.session.get(
            url = "https://signup.live.com/signup",
            headers = headers,
        )
        lgn_url = findall(r'<a href="(.*?)">', res.text)[0]
        lgn_url = Utils.decode_url(findall(r'<a href="(.*?)">', res.text)[0])
        cookie1 = res.cookies
        self.amsc = cookie1.get("amsc")
        self.cookies = {
            "amsc": self.amsc
        }
        
        headers["Host"] = "login.live.com"
        res = self.session.get(
            url = lgn_url,
            headers = headers,
            cookies = self.cookies
        )
        self.uaid = res.cookies.get("uaid")
        
        headers["Host"] = "signup.live.com"
        res = self.session.get(
            url = f"https://signup.live.com/signup?lic=1&uaid={self.uaid}",
            headers = headers,
            cookies = self.cookies
        )

        match = search(r'Key="([^"]+)";', res.text)
        if match:
            self.key = match.group(1)

        match = search(r'randomNum="([^"]+)";', res.text)
        if match:
            self.randomNum = match.group(1)

        match = search(r'"apiCanary":"([^"]+)",', res.text)
        if match:
            self.apiCanary = match.group(1)

        match = search(r'"sHipFid":"([^"]+)",', res.text)
        if match:
            self.sHipFid = match.group(1)

        match = search(r'"urlDfp":"([^"]+)",', res.text)
        if match:
            self.fptLink = match.group(1)

        match = search(r'SKI="([^"]+)";', res.text)
        if match:
            self.ski = match.group(1)

        match = search(r'"hpgid":([^"]+),', res.text)
        if match:
            self.hpgid = match.group(1)

        match = search(r'"iUiFlavor":([^"]+),', res.text)
        if match:
            self.iUiFlavor = match.group(1)

        match = search(r'"iScenarioId":([^"]+),', res.text)
        if match:
            self.iScenarioId = match.group(1)

        match = search(r'"sSiteId":"([^"]+)"', res.text)
        if match:
            self.siteId = match.group(1)
        
        headers["Host"] = "fpt.live.com"
        headers["Referer"] = "signup.live.com"
        res = self.session.get(
            url = self.fptLink,
            headers = headers,
            cookies = self.cookies
        )
        cookie4 = res.cookies
        self.muid = cookie4.get("MUID")

        soup = BeautifulSoup(res.text, "html.parser")

        script_content = None

        for script in soup.find_all("script"):
            if script.string and "txnId" in script.string:
                script_content = script.string

                break

        if script_content:
            self.txnId = search(r"txnId='([^']+)'", script_content).group(1)
            self.ticks = search(r"ticks='([^']+)'", script_content).group(1)
            self.rid = search(r"rid='([^']+)'", script_content).group(1)
            self.authKey = search(r"authKey='([^']+)'", script_content).group(1)
            self.cid = search(r"cid='([^']+)'", script_content).group(1)

    def sessionRequests(self):
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
            "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }

        headers["Host"] = "fpt2.live.com"
        headers["Referer"] = "https://fpt.live.com/"
        res = self.session.get(
            url = f"https://fpt2.microsoft.com/Clear.HTML?ctx=Ls1.0&wl=False&session_id={self.txnId}&id={self.rid}&w={self.ticks}&tkt={self.authKey}&CustomerId={self.cid}",
            headers = headers,
        )

        decoded = Utils.decode_url(self.apiCanary)
        
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "canary": decoded,
            "client-request-id": self.uaid,
            "Connection": "keep-alive",
            "Content-type": "application/json; charset=utf-8",
            "correlationId": self.uaid,
            "Host": "signup.live.com",
            "hpgact": "0",
            "hpgid": self.hpgid,
            "Origin": "https://signup.live.com",
            "Referer": f"https://signup.live.com/signup?lic=1&uaid={self.uaid}",
            "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }
        res = self.session.post(
            url = f"https://signup.live.com/API/EvaluateExperimentAssignments",
            headers = headers,
            cookies = self.cookies,
            json = {
                "clientExperiments": [
                    {
                        "parallax": "enableplaintextforsignupexperiment",
                        "control": "enableplaintextforsignupexperiment_control",
                        "treatments": [
                            "enableplaintextforsignupexperiment_treatment"
                        ]
                    }
                ]
            }
        )

        canary = res.json()["apiCanary"]

        headers["canary"] = canary
        res = self.session.post(
            url = f"https://signup.live.com/API/CheckAvailableSigninNames",
            headers = headers,
            cookies = self.cookies,
            json = {
                "includeSuggestions": True,
                "signInName": self.email,
                "uiflvr": self.iUiFlavor,
                "scid": self.iScenarioId,
                "uaid": self.uaid,
                "hpgid": self.hpgid
            }
        )

        self.canary = res.json()["apiCanary"]

    def generateAccount(self):
        encryptor = Encryptor()
        encrypted_value = encryptor.encrypt_value(config["script"]["password"], self.randomNum, self.key)

        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.9",
            "canary": self.canary,
            "client-request-id": self.uaid,
            "Connection": "keep-alive",
            "Content-type": "application/json; charset=utf-8",
            "Cookie": f"amsc={self.amsc}; MicrosoftApplicationsTelemetryDeviceId=4329ea0e-aa3a-47c4-b986-dbd1d504b96e; ai_session={Utils.ai_session()}; MUID={self.muid}",
            "correlationId": self.uaid,
            "Host": "signup.live.com",
            "hpgact": "0",
            "hpgid": self.hpgid,
            "Origin": "https://signup.live.com",
            "Referer": f"https://signup.live.com/signup?lic=1&uaid={self.uaid}",
            "sec-ch-ua": "\"Not/A)Brand\";v=\"8\", \"Chromium\";v=\"126\", \"Google Chrome\";v=\"126\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        }
        res = self.session.post(
            url = f"https://signup.live.com/API/CreateAccount",
            headers = headers,
            json = {
                "BirthDate": "23:12:1998",
                "CheckAvailStateMap": [
                    f"{self.email}:false"
                ],
                "Country": "FR",
                "EvictionWarningShown": [],
                "FirstName": self.name,
                "IsRDM": False,
                "IsOptOutEmailDefault": False,
                "IsOptOutEmailShown": 1,
                "IsOptOutEmail": False,
                "IsUserConsentedToChinaPIPL": False,
                "LastName": self.lname.upper(),
                "LW": 1,
                "MemberName": self.email.upper(),
                "RequestTimeStamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "ReturnUrl": "",
                "SignupReturnUrl": "",
                "SuggestedAccountType": "EASI",
                "SiteId": self.siteId,
                "VerificationCode": "",
                "VerificationCodeSlt": "",
                "WReply": "",
                "MemberNameChangeCount": 2,
                "MemberNameAvailableCount": 1,
                "MemberNameUnavailableCount": 1,
                "CipherValue": encrypted_value,
                "SKI": self.ski,
                "Password": config["script"]["password"],
                "uiflvr": self.iUiFlavor,
                "scid": self.iScenarioId,
                "uaid": self.uaid,
                "hpgid": self.hpgid
            }
        )
        res_data = json.loads(res.json()["error"]["data"])

        raid = res_data["riskAssessmentDetails"]
        rmrid = res_data["repMapRequestIdentifierDetails"]
        arkoseBlob = res_data["arkoseBlob"]
        
        solve = Captcha()._solve_captcha(arkoseBlob)

        if solve is None or solve == "":
            return
        
        Print.inf(f"Succesfully Solved Captcha. [{solve[:50]}...] (FunCaptchaProxy)")

        encryptor = Encryptor()
        encrypted_value = encryptor.encrypt_value(config["script"]["password"], self.randomNum, self.key)

        res = self.session.post(
            url = f"https://signup.live.com/API/CreateAccount",
            headers = headers,
            json = {
                "BirthDate": "23:12:1998",
                "CheckAvailStateMap": [
                    f"{self.email}:false"
                ],
                "Country": "FR",
                "EvictionWarningShown": [],
                "FirstName": self.name,
                "IsRDM": False,
                "IsOptOutEmailDefault": False,
                "IsOptOutEmailShown": 1,
                "IsOptOutEmail": False,
                "IsUserConsentedToChinaPIPL": False,
                "LastName": self.lname,
                "LW": 1,
                "MemberName": self.email,
                "RequestTimeStamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "ReturnUrl": "",
                "SignupReturnUrl": "",
                "SuggestedAccountType": "EASI",
                "SiteId": self.siteId,
                "VerificationCode": "",
                "VerificationCodeSlt": "",
                "WReply": "",
                "MemberNameChangeCount": 2,
                "MemberNameAvailableCount": 1,
                "MemberNameUnavailableCount": 1,
                "CipherValue": encrypted_value,
                "SKI": self.ski,
                "Password": config["script"]["password"],
                "RiskAssessmentDetails": raid,
                "RepMapRequestIdentifierDetails": rmrid,
                "HFId": self.sHipFid,
                "HPId": "B7D8911C-5CC8-A9A3-35B0-554ACEE604DA",
                "HSol": solve,
                "HType": "enforcement",
                "HId": solve,
                "uiflvr": self.iUiFlavor,
                "scid": self.iScenarioId,
                "uaid": self.uaid,
                "hpgid": self.hpgid
            }
        )

        if res.status_code == 200:
            Print.vert("Account Created", Personal = f"{self.name} {self.lname}", Email = self.email, Password = config["script"]["password"])

            with open("users.txt", "a+") as file:
                file.write(f"{self.email}:{config["script"]["password"]}\n")
        else:
            Print.error("Failed Account Creation")
            print(res.text)

def main():
    while True:
        ok = Outlook()

        ok.getFirstValues()
        ok.sessionRequests()
        ok.generateAccount()


if __name__ == "__main__":
    try:
        with ThreadPoolExecutor(max_workers = 10) as executor:
            while True:
                executor.submit(main)
    except KeyboardInterrupt:
        exit(0)