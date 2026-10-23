from typing import Optional

def parse_device_info(user_agent: Optional[str]) -> str:
    """Parses a User-Agent string into a clean, human-readable Device/Browser description."""
    if not user_agent:
        return "Unknown Device"

    ua = user_agent.lower()

    # Detect Operating System / Platform
    os_name = "Unknown OS"
    if "windows" in ua:
        os_name = "Windows"
    elif "iphone" in ua:
        os_name = "iPhone"
    elif "ipad" in ua:
        os_name = "iPad"
    elif "macintosh" in ua or "mac os x" in ua:
        os_name = "macOS"
    elif "android" in ua:
        os_name = "Android"
    elif "linux" in ua:
        os_name = "Linux"

    # Detect Browser / Client
    browser_name = "Unknown Browser"
    if "edg/" in ua or "edge/" in ua:
        browser_name = "Microsoft Edge"
    elif "opr/" in ua or "opera" in ua:
        browser_name = "Opera"
    elif "firefox/" in ua:
        browser_name = "Firefox"
    elif "chrome" in ua or "chromium" in ua or "crios" in ua:
        browser_name = "Chrome"
    elif "safari" in ua:
        browser_name = "Safari"
    elif "curl" in ua:
        browser_name = "cURL"
    elif "python" in ua or "pytest" in ua or "testclient" in ua:
        browser_name = "Automated Client"
    elif "postman" in ua:
        browser_name = "Postman"

    return f"{browser_name} on {os_name}"
