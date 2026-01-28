#!/usr/bin/env python3
import requests
import re

# Read the markdown file
markdown_file = r"e:\retr0ds_blog\content\posts\bi0sCTF_Ransomware\index.md"
with open(markdown_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Find first HackMD URL
hackmd_pattern = r'!\[image\]\((https://hackmd\.io/_uploads/[^\)]+)\)'
match = re.search(hackmd_pattern, content)

if match:
    url = match.group(1)
    print(f"Testing URL: {url}\n")
    
    # Try without following redirects first to see the Location header
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    
    try:
        print("Attempting HEAD request...")
        head_response = session.head(url, timeout=30, allow_redirects=False)
        print(f"HEAD Status: {head_response.status_code}")
        print(f"HEAD Headers: {dict(head_response.headers)}")
        
        print("\nAttempting GET request without redirects...")
        get_response = session.get(url, timeout=30, allow_redirects=False)
        print(f"GET Status: {get_response.status_code}")
        print(f"Location header: {get_response.headers.get('location')}")
        print(f"Content-Length: {len(get_response.content)}")
        
        # If there's a Location header, try that
        if get_response.status_code in [301, 302, 303, 307, 308]:
            location = get_response.headers.get('location')
            if location:
                print(f"\nFollowing redirect to: {location}")
                redirect_response = session.get(location, timeout=30)
                print(f"Redirect Status: {redirect_response.status_code}")
                print(f"Redirect Content-Length: {len(redirect_response.content)}")
                if redirect_response.content:
                    print(f"✓ Got {len(redirect_response.content)} bytes from redirect")
            
    except Exception as e:
        print(f"✗ Error: {e}")
