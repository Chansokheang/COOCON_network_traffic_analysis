"""This is the additional criterial into the network analysis"""
import json
import re

from urllib.parse import urlparse
from typing import List, Dict, Set


def check_priority_criterial(event: dict) -> bool:
    """
    Check if the event meets the priority criteria.
    - initialPriority is "VeryHigh" or "High"
    - isSameSite is true
    - method is "POST"
    - postData must not be "{}" (exclude empty JSON objects)
    """
    try:
        request = event["data"]["request"]
        return (
            request.get("initialPriority") in ["VeryHigh", "High"] and
            request.get("isSameSite") and
            request.get("method") == "POST" and 
            "postData" in request and
            request["postData"] != "{}"
        )
    except Exception as e:
        return False

def should_exclude_url(url: str, excluded_exts: list) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in excluded_exts)

def filter_network_log_by_dynamic_url(
    input_filename,
    output_filename,
    password,
    extra_keywords=None
):
    excluded_extensions = [
        ".js", ".css", ".jsp", ".png", ".jpg", ".jpeg",
        ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"
    ]

    included_url_keywords = [
        "retrieve",
        "api",
        "jcaptcha.jpg",
        "https://www.nhis.or.kr/nhis/etc/personalSignLoginNew.do",  # NHIS login page
        "https://banking.nonghyup.com/servlet/IPCNPA000I.view",     # NH Bank login page
        "https://obank.kbstar.com/quics?page=C055068&QSL=F#loading",   # KB Bank login page
        "https://www.hometax.go.kr/websquare/websquare.html?w2xPath=/ui/pp/index.xml", # Hometax login page
        "https://www.gov.kr/nlogin/?Mcode=10003"
    ]

    # Merge extra_keywords if provided
    if extra_keywords:
        if isinstance(extra_keywords, list):
            included_url_keywords.extend(extra_keywords)
        elif isinstance(extra_keywords, str):
            included_url_keywords.append(extra_keywords)
    
    filtered_log = []
    auth_endpoints_found = set()

    try:
        with open(input_filename, "r", encoding="utf-8") as f:
            log_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {input_filename}")
        return
    except json.JSONDecodeError:
        print(f"❌ Failed to decode JSON: {input_filename}")
        return

    # Compile the regex pattern once for efficiency
    password_pattern = re.compile(re.escape(password))

    for event in log_data:
        event_type = event.get("type")

        if event_type == "Network.webSocketFrameReceived" or event_type == "Network.webSocketFrameSent":
            payload = event["data"]["response"]["payloadData"]
            
            # First check for password using regex
            if password and password_pattern.search(payload):
                filtered_log.append(event)
                continue
            
            # Then check for non-empty return values
            elif (
                ",\"ReturnValue\":\"\"," not in payload
                and ",\"ReturnValue\":\"0\"," not in payload
            ):
                filtered_log.append(event)
            
            continue

        if event_type == "Network.requestWillBeSent":
            try:
                request = event["data"]["request"]
                if request["hasPostData"] == True:
                    url = request["url"].lower()

                    # Check for password in postData using regex
                    if "postData" in request and password and password_pattern.search(request["postData"]):
                        filtered_log.append(event)
                        continue

                    # Check if request meets priority criteria
                    if check_priority_criterial(event):
                        filtered_log.append(event)
                        continue
                    
                    if should_exclude_url(url, excluded_extensions):
                        continue  # Skip static resources

                    filtered_log.append(event)  # No extension or keyword block — keep
                else:
                    continue
            except KeyError:
                continue

    try:
        with open(output_filename, "w", encoding="utf-8") as f_out:
            json.dump(filtered_log, f_out, indent=2, ensure_ascii=False)
        print(f"✅ Filtered log saved to '{output_filename}' with {len(filtered_log)} entries.")
        
        # Print summary of found authentication endpoints
        if auth_endpoints_found:
            print("\n🔍 Found Authentication Endpoints:")
            for endpoint in sorted(auth_endpoints_found):
                print(f"  - {endpoint}")
    except IOError:
        print(f"❌ Failed to write output file: {output_filename}")


if __name__ == "__main__":
    input_file = "network_log_tab_845071459_1749778875762.json"
    output_file = "filtered_network_log_priority_kbstar.json"
    password = "pncsoft1!!"
    filter_network_log_by_dynamic_url(input_file, output_file,password)