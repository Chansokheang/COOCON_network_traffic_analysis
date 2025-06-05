import json
import re
from urllib.parse import urlparse

def should_exclude_url(url: str, excluded_exts: list) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in excluded_exts)

def should_include_url(url: str, included_keywords: list) -> bool:
    url = url.lower()
    return any(keyword in url for keyword in included_keywords)

def filter_network_log_by_dynamic_url(
    input_filename="network_log.json",
    output_filename="filtered_network_log.json"
):
    excluded_extensions = [
        ".js", ".css", ".jsp", ".png", ".jpg", ".jpeg",
        ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot"
    ]

    included_url_keywords = [
        "retrieve",
        "api",
        "jcaptcha.jpg"
        "https://www.nhis.or.kr/nhis/etc/personalSignLoginNew.do", # NHIS login page
        "https://banking.nonghyup.com/servlet/IPCNPA000I.view",     # NH Bank login page
        "https://obank.kbstar.com/quics?page=C055068&QSL=F#loading"   # KB Bank login page
    ]

    filtered_log = []

    try:
        with open(input_filename, "r", encoding="utf-8") as f:
            log_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ File not found: {input_filename}")
        return
    except json.JSONDecodeError:
        print(f"❌ Failed to decode JSON: {input_filename}")
        return

    for event in log_data:
        event_type = event.get("type")

        if event_type == "Network.webSocketFrameReceived":
            payload = event["data"]["response"]["payloadData"]
            if (
                ",\"ReturnValue\":\"\"," not in payload
                and ",\"ReturnValue\":\"0\"," not in payload
            ):
                filtered_log.append(event)
            continue

        if event_type == "Network.requestWillBeSent":
            try:
                if event["data"]["request"]["hasPostData"] == True:
                    url = event["data"]["request"]["url"].lower()
                    if is_invalid_scheme(url):
                        continue 
                    if should_include_url(url, included_url_keywords):
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
    except IOError:
        print(f"❌ Failed to write output file: {output_filename}")

def is_invalid_scheme(url: str) -> bool:
    """Exclude embedded or script URLs like data:, blob:, javascript:"""
    invalid_schemes = ["data:", "blob:", "javascript:", "http:", "localhost:"]
    if any(url.lower().startswith(scheme) for scheme in invalid_schemes):
        return True
    if re.match(r"^https://\d", url):
        return True
    return False

if __name__ == "__main__":
    input_file = "network_log_tab_1091069991_1749126956709.json"
    output_file = "filtered_network_log_final_nhis.json"
    filter_network_log_by_dynamic_url(input_file, output_file)
