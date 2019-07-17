#!/usr/bin/python3
import traceback
import platform
import sys
import os
import re
import time
import hashlib
import subprocess
import json
from threading import Timer, Lock
import _thread as thread

class Config():
    def __init__(self, configuration=None):
        if not None is configuration:
            self.config = configuration
        else:
            self.config = {
                "linux_cmd": ["xdg-open"],
                "windows_cmd": ["C:\\windows\\system32\\cmd.exe", "/c", "start"],
                "url_cmd": ["firefox-esr", "--new-tab"],
                "default_url": "https://duckduckgo.com",
                "sharedurls": "/home/analyst/malware/.sharedurls",
                "attachments_path": "/home/analyst/malware/",
                "UA": "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko",
            }

    def __getitem__(self, key):
        if key in self.config:
            return self.config[key]
        else:
            return None

    def loadconfig(self):
        try:
            with open("openlinks_config.json") as f:
                self.config = json.loads(f.read())
            print("Opened openlinks_config.json")
        except Exception as e:
            print(str(e))
        try:
            with open("openlinks_config.json", "w+") as f:
                f.write(json.dumps(self.config, indent=4, sort_keys=True))
        except Exception as e:
            print(str(e))


class OpenPhish(Config):
    def __init__(self, config):
        super(OpenPhish, self).__init__()
        self.sharedurls = ""
        self.srv = None
        self.sharedurls = config["sharedurls"]
        self.pd = re.compile(r"https?:\/\/([a-zA-Z0-9-\.]*)/?.*")

    def prettylist(self, l):
        r = ''
        s = []
        if type(l) is list:
            for e in l:
                if type(e) is dict:
                    r += self.dict_print(e)
                else:
                    s.append(str(e))

        return r+(','.join(s).strip(','))

    def dict_print(self, r):
        out = ''
        for k in r:
            if type(r[k]) is dict:
                out += "\t"+k+":\n"
                out += "\t"+self.dict_print(r[k])
            elif type(r[k]) is list:
                out += "\t"+str(k)+": "+self.prettylist(r[k])+"\n"
            else:
                out += "\t"+str(k)+": "+str(r[k])+"\n"
        return out

    def ioctype(self, indicator):
        validIP = re.compile(
            r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$")
        validDomain = re.compile(r"^[\w\.-]{4,}$")
        validURL = re.compile(r"^\w+://[\w\.-]{4,}.*$")
        validEmail = re.compile(r"^[\w\d\.-]+@[\w\d\.-]+\.[\w\d\.-]+$")
        validMD5 = re.compile(r"^[a-fA-F\d]{32}$")
        validSHA1 = re.compile(r"^[a-fA-F\d]{40}$")
        validSHA224 = re.compile(r"^[a-fA-F\d]{56}$")
        validSHA384 = re.compile(r"^[a-fA-F\d]{96}$")
        validSHA256 = re.compile(r"^[a-fA-F\d]{64}$")
        validSHA512 = re.compile(r"^[a-fA-F\d]{128}$")

        if not None is re.match(validURL, indicator):
            return "url"
        elif (not None is re.match(validSHA512, indicator)) or (not None is re.match(validSHA256, indicator)) or (not None is re.match(validSHA384, indicator)) or (not None is re.match(validSHA224, indicator)) or (not None is re.match(validSHA1, indicator)):
            return "file"
        elif not None is re.match(validDomain, indicator):
            return "domain"
        elif not None is re.match(validIP, indicator):
            return "ip"

        else:
            return None

    def main(self):
        config = self.config
        if len(sys.argv) > 1:  # command line argument.
            lookup = sys.argv[1]
            isurl = re.match(self.pd, lookup)
            if not None is isurl:
                try:
                    urlmonitor = URLMonitor(config)
                    subprocess.call(
                        self.config['url_cmd']+[lookup], shell=False)
                except Exception as e:
                    traceback.print_exc()
                    sys.exit(1)

            sys.exit(0)

        try:
            filemonitor = FileMonitor(config)
            urlmonitor = URLMonitor(config)

            thread.start_new_thread(urlmonitor.monitor, ())
            print("Started URL monitor")
            thread.start_new_thread(filemonitor.monitor, ())
            print("Started File monitor")
        except Exception as e:
            print("Exception while starting monitor threads")
            traceback.print_exc()

        print("[+] Entering main loop.")
        while True:
            try:
                time.sleep(5.0)
            except Exception as e:
                print("Main loop exception")
                traceback.print_exc()


class URLMonitor(OpenPhish):
    def __init__(self, config):
        super(URLMonitor, self).__init__(config)
        self.opened = set()

    def monitor(self):
        config = self.config
        try:
            print("[!] Monitoring URLs in file: "+self.sharedurls)
            while True:
                time.sleep(0.7)
                with open(self.sharedurls, "r+") as f:
                    lines = f.read()
                    url = ''
                    for url in lines.splitlines():
                        if url.strip().startswith("http") and not url in self.opened:
                            url = url.strip("\r\n")
                            url = url.strip("\n").strip()
                            self.opened.add(url)
                            print("Opened: {}".format(url))
                            subprocess.call(
                                self.config['url_cmd']+[url], shell=False)
                            with open(self.sharedurls, "w+") as f:
                                f.write("")
                        elif url and url in self.opened:
                            print('Already processed ' +
                                  url+' --- Not opening it again.')

                            with open(self.sharedurls, "w+") as f:
                                f.write("")
        except Exception as e:
            traceback.print_exc()


class FileMonitor(OpenPhish):
    def __init__(self, config):
        super(FileMonitor, self).__init__(config)
        self.prefix = config["attachments_path"]
        self.config['platform'] = platform.system()

    def openfile(self, fn):
        if os.fork() == 0:
            if self.config['platform'] == "Linux":
                subprocess.call(self.config['linux_cmd']+[fn])
                os._exit(0)
            elif self.config['platform'] == "Windows":
                subprocess.call(self.config['windows_cmd']+[fn])
                os._exit(0)

    def sha256hash(self, filename):
        data = ''
        try:
            with open(filename, 'rb') as f:
                data = f.read(1000000)
        except:
            pass
        if not data:
            return None
        return hashlib.sha256(data).hexdigest()

    def monitor(self):
        prefix = self.prefix
        sha256 = ''

        print("[!] Starting File monitor thread for directory:"+prefix)
        processed = set()
        with open("processed.log", "r") as f:
            for l in f.read().split("\n"):
                if len(l) > 1:
                    processed.add(l)
        pf = ''
        while True:
            try:
                files = os.listdir(prefix)

                for file in files:
                    # print(file)
                    time.sleep(1/100.0)
                    pf = prefix+file
                    if file.startswith(".") or (not "." in file):
                        continue
                    else:
                        sha256 = self.sha256hash(pf)
                    if not sha256 in processed:
                        # time.sleep(2)
                        print("+"+("*"*80)+"+")
                        print("Processing:"+pf)
                        print(sha256)
                        vturl = '''https://www.virustotal.com/#/file/{}/detection'''.format(
                            str(sha256).strip())
                        print(vturl)
                        processed.add(sha256)
                        with open("processed.log", "a+") as f:
                            f.write(sha256+"\n")
                        self.openfile(pf)
            except Exception as e:
                print(e)
                traceback.format_exc()
                processed.add(sha256)
                continue


if __name__ == "__main__":
    config = Config()
    config.loadconfig()
    iocmon = OpenPhish(config)
    try:
        iocmon.main()
    except Exception as e:
        traceback.print_exc()
