#!/usr/bin/env python3
import re
import os
import subprocess
from pathlib import Path

# File paths
markdown_file = r"e:\retr0ds_blog\content\posts\bi0sCTF_Ransomware\index.md"
image_dir = r"e:\retr0ds_blog\content\posts\bi0sCTF_Ransomware\images"

# Create images directory if it doesn't exist
Path(image_dir).mkdir(parents=True, exist_ok=True)

# Read the markdown file
with open(markdown_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Find all HackMD image URLs
hackmd_pattern = r'!\[image\]\((https://hackmd\.io/_uploads/[^\)]+)\)'
matches = list(re.finditer(hackmd_pattern, content))

print(f"Found {len(matches)} HackMD image URLs to download\n")

# Track replacements
replacements = []
downloaded_count = 0
failed_count = 0

for i, match in enumerate(matches, 1):
    url = match.group(1)
    filename = url.split('/')[-1]
    local_path = os.path.join(image_dir, filename)
    
    try:
        print(f"[{i}/{len(matches)}] Downloading: {filename}...", end=' ', flush=True)
        
        # Use curl to download - it handles redirects automatically
        cmd = [
            'curl',
            '-L',  # Follow redirects
            '--compressed',
            '-A', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            '-m', '30',  # 30 second timeout
            '-o', local_path,
            url
        ]
        
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        if result.returncode == 0 and os.path.exists(local_path):
            file_size = os.path.getsize(local_path)
            
            if file_size > 0:
                print(f"✓ ({file_size} bytes)")
                replacements.append({'old_url': url, 'new_url': f'images/{filename}'})
                downloaded_count += 1
            else:
                print(f"✗ Empty file")
                os.remove(local_path)
                failed_count += 1
        else:
            print(f"✗ Download failed")
            if os.path.exists(local_path):
                os.remove(local_path)
            failed_count += 1
            
    except Exception as e:
        print(f"✗ Error: {str(e)}")
        failed_count += 1

# Replace URLs in content
for replacement in replacements:
    old_markdown = f'![image]({replacement["old_url"]})'
    new_markdown = f'![image]({replacement["new_url"]})'
    content = content.replace(old_markdown, new_markdown)

# Write the updated markdown file
with open(markdown_file, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"\n{'='*60}")
print(f"✓ Downloaded: {downloaded_count} images")
if failed_count > 0:
    print(f"✗ Failed: {failed_count} images")
print(f"✓ Updated markdown file with local image paths")
print(f"{'='*60}")
