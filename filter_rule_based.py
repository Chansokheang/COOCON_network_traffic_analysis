import json
import re
from urllib.parse import urlparse
from typing import List, Dict, Set

# Common authentication endpoint patterns
AUTH_PATTERNS = {
    # Login endpoints
    'login': [
        r'/login',
        r'/signin',
        r'/auth',
        r'/authenticate',
        r'/sign-in',
        r'/log-in',
        r'/user/login',
        r'/api/auth',
        r'/api/login',
        r'/api/signin',
        r'/api/v1/auth',
        r'/api/v1/login',
        r'/api/v2/auth',
        r'/api/v2/login',
        r'/oauth2',
        r'/saml',
        r'/sso',
    ],
    # Session management
    'session': [
        r'/session',
        r'/token',
        r'/refresh',
        r'/validate',
        r'/verify',
        r'/check',
        r'/status',
    ],
    # Security features
    'security': [
        r'/captcha',
        r'/2fa',
        r'/mfa',
        r'/otp',
        r'/security',
        r'/verify',
        r'/validation',
    ],
    # Banking specific
    'banking': [
        r'/personalSignLogin',
        r'/IPCNPA000I',
        r'/quics',
        r'/websquare',
        r'/nlogin',
    ]
}

def compile_patterns(patterns: Dict[str, List[str]]) -> Dict[str, List[re.Pattern]]:
    """Compile regex patterns for efficient matching"""
    return {
        category: [re.compile(pattern, re.IGNORECASE) for pattern in pattern_list]
        for category, pattern_list in patterns.items()
    }

def matches_auth_pattern(url: str, compiled_patterns: Dict[str, List[re.Pattern]]) -> bool:
    """Check if URL matches any authentication pattern"""
    url = url.lower()
    for category_patterns in compiled_patterns.values():
        for pattern in category_patterns:
            if pattern.search(url):
                return True
    return False

def should_exclude_url(url: str, excluded_exts: list) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in excluded_exts)

def should_include_url(url: str, included_keywords: list, compiled_patterns: Dict[str, List[re.Pattern]]) -> bool:
    """Enhanced URL inclusion check with pattern matching"""
    url = url.lower()
    
    # Check against included keywords
    if any(keyword in url for keyword in included_keywords):
        return True
        
    # Check against authentication patterns
    if matches_auth_pattern(url, compiled_patterns):
        return True
        
    return False

def filter_network_log_by_dynamic_url(
    input_filename="network_log.json",
    output_filename="filtered_network_log.json",
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

    # Compile authentication patterns
    compiled_patterns = compile_patterns(AUTH_PATTERNS)
    
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
                    if should_include_url(url, included_url_keywords, compiled_patterns):
                        filtered_log.append(event)
                        # Track found authentication endpoints
                        for category, patterns in compiled_patterns.items():
                            for pattern in patterns:
                                if pattern.search(url):
                                    auth_endpoints_found.add(f"{category}: {pattern.pattern}")
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

def is_invalid_scheme(url: str) -> bool:
    """Exclude embedded or script URLs like data:, blob:, javascript:"""
    invalid_schemes = ["data:", "blob:", "javascript:", "http:", "localhost:"]
    if any(url.lower().startswith(scheme) for scheme in invalid_schemes):
        return True
    if re.match(r"^https://\d", url):
        return True
    return False

if __name__ == "__main__":
    input_file = "network_log_tab_nonghyup.json"
    output_file = "filtered_network_log_final_nonghyup.json"
    filter_network_log_by_dynamic_url(input_file, output_file)
