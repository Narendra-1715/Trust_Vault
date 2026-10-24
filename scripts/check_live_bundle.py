import urllib.request
import re
import ssl

ctx = ssl.create_default_context()
req = urllib.request.Request('https://trustvault-ui.onrender.com/', headers={'User-Agent': 'Mozilla/5.0'})

with urllib.request.urlopen(req, timeout=10, context=ctx) as res:
    html = res.read().decode('utf-8')
    print('HTML length:', len(html))
    match = re.search(r'src="(/assets/index-[^"]+\.js)"', html)
    if match:
        js_path = match.group(1)
        print('Live JS script:', js_path)
        js_url = 'https://trustvault-ui.onrender.com' + js_path
        req_js = urllib.request.Request(js_url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req_js, timeout=10, context=ctx) as res_js:
            js = res_js.read().decode('utf-8')
            print('JS bundle length:', len(js))
            # Find URLs in bundle
            m = re.findall(r'https://[a-zA-Z0-9\.-]+onrender\.com[^\s"\'`)]*', js)
            print('Render URLs in JS bundle:', set(m))
            if 'trustvault-api' in js:
                print("Found 'trustvault-api' in bundle!")
            else:
                print("'trustvault-api' NOT found in bundle!")
    else:
        print('No index.js found in HTML:', html[:200])
