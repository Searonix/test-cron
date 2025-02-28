import requests
import os
import urllib3
import logging
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
urllib3.disable_warnings()

API_URL = os.getenv("API_URL")  
HEADERS = {
    "User-agent": os.getenv("USER_AGENT"),  
    # "x-API-Id": os.getenv("X-API-ID"),  
    # "x-API-Key": os.getenv("X-API-KEY")  
}

os.makedirs("data", exist_ok=True)
os.makedirs("log", exist_ok=True)
current_time = datetime.now().strftime("%Y-%m-%d_%H%M%S")
DATA_FILE = f"data/{current_time}_data.txt"
LOG_FILE = f"log/{current_time}.log"
MAIN_IP_FILE = "waf-feeds.txt"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.getLogger().addHandler(console_handler)

def fetch_api_data():
    """ดึงข้อมูลจาก API"""
    try:
        response = requests.get(API_URL, headers=HEADERS, verify=False) 
        
        if response.status_code == 200:
            data = response.json()
            logging.info(f"API response structure: {type(data)}")
            if isinstance(data, list) and len(data) > 0:
                logging.info(f"First item type: {type(data[0])}")
                logging.info(f"Sample data: {data[0]}")
            logging.info(f"Successfully fetched {len(data)} items from API.")
            return extract_ips(data) 
        else:
            logging.error(f"Error fetching data: {response.status_code}")
            return None
    except Exception as e:
        logging.error(f"Exception in fetch_api_data: {e}")
        return None

def extract_ips(data):
    """ดึงค่า IP จาก JSON"""
    try:
        ip_list = []
        
        # ตรวจสอบว่าข้อมูลเป็นรายการของ IP address โดยตรงหรือไม่
        if isinstance(data, list):
            for item in data:
                # กรณีข้อมูลเป็นรายการของ IP address โดยตรง
                if isinstance(item, str):
                    ip = item.strip()
                    if ip:  # ตรวจสอบว่า IP ไม่ใช่ string ว่าง
                        ip_list.append(ip)
                # กรณีข้อมูลเป็นรายการของ dictionary
                elif isinstance(item, dict) and "dominant_attack_ip" in item:
                    if isinstance(item["dominant_attack_ip"], dict) and "ip" in item["dominant_attack_ip"]:
                        ip = item["dominant_attack_ip"]["ip"].strip()
                        if ip:
                            ip_list.append(ip)
        
        logging.info(f"Extracted {len(ip_list)} IPs")
        return ip_list
    except Exception as e:
        logging.error(f"Error extracting IPs: {e}")
        return []

def load_existing_ips():
    """โหลด IP ที่เคยบันทึกไว้"""
    try:
        if os.path.exists(MAIN_IP_FILE):  
            with open(MAIN_IP_FILE, "r") as file:
                return set(line.strip() for line in file.read().splitlines() if line.strip())
        return set()
    except Exception as e:
        logging.error(f"Error loading existing IPs: {e}")
        return set()

def save_new_ips(new_ips):
    """บันทึกเฉพาะ IP ที่ไม่ใช่ค่าว่างและเรียงลำดับ"""
    try:
        filtered_ips = {ip.strip() for ip in new_ips if ip.strip()}
        
        if not filtered_ips:
            logging.info("No valid IPs to save")
            return
        
        all_ips = sorted(load_existing_ips() | filtered_ips)
        
        with open(MAIN_IP_FILE, "w") as file:  
            file.write("\n".join(all_ips) + "\n")
        
        with open(DATA_FILE, "a") as file:  
            file.write(f"# New IPs added on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            for ip in sorted(filtered_ips):  
                file.write(ip + "\n")
        
        logging.info(f"Added {len(filtered_ips)} new IPs")
    except Exception as e:
        logging.error(f"Error saving new IPs: {e}")

def delta_query():
    """เช็คเฉพาะ IP ใหม่และบันทึก"""
    try:
        existing_ips = load_existing_ips()
        logging.info(f"Loaded {len(existing_ips)} existing IPs")
        
        fetched_ips = fetch_api_data()
        if not fetched_ips:
            logging.warning("No data fetched from API!")
            return
        
        fetched_ips_set = set(fetched_ips)
        new_ips = fetched_ips_set - existing_ips
        
        if new_ips:
            logging.info(f"Found {len(new_ips)} new IPs")
            save_new_ips(new_ips)  
        else:
            logging.info("No new IPs found!")
    except Exception as e:
        logging.error(f"Error in delta_query: {e}")

if __name__ == "__main__":
    delta_query()