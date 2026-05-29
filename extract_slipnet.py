import requests
import zipfile
import os
import sys
from pathlib import Path

def download_apk(url, output="slipnet.apk"):
    print(f"📥 دانلود APK از: {url}")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(output, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"✅ دانلود کامل شد: {output}")
    return output

def extract_so_files(apk_path, extract_dir="extracted"):
    print("📦 استخراج فایل‌های .so ...")
    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith('.so'):
                zip_ref.extract(file, extract_dir)
                print(f"استخراج: {file}")
    return extract_dir

def extract_strings(so_path):
    try:
        with open(so_path, 'rb') as f:
            data = f.read()
        strings = []
        current = ''
        for b in data:
            if 32 <= b <= 126 or b in (9, 10, 13):
                current += chr(b)
            else:
                if len(current) >= 8:
                    strings.append(current.strip())
                current = ''
        if len(current) >= 8:
            strings.append(current.strip())
        return strings
    except:
        return []

def search_crypto(strings):
    keywords = ['aes', 'gcm', 'key', 'encrypt', 'decrypt', 'iv', 'nonce', 'slipnet', 
                'secret', 'hardcode', '0x', 'hkdf', 'ntor', 'x25519', 'obfs']
    return [s for s in strings if any(k in s.lower() for k in keywords)]

def main(apk_url):
    apk_file = "slipnet.apk"
    extract_dir = "extracted_so"
    
    download_apk(apk_url, apk_file)
    so_dir = extract_so_files(apk_file, extract_dir)
    
    all_strings = []
    crypto_findings = []
    
    for root, _, files in os.walk(so_dir):
        for file in files:
            if file.endswith('.so'):
                path = os.path.join(root, file)
                print(f"🔍 پردازش: {file}")
                strings = extract_strings(path)
                all_strings.extend(strings)
                crypto = search_crypto(strings)
                if crypto:
                    print(f"   🔑 {len(crypto)} مورد مرتبط پیدا شد")
                    crypto_findings.extend(crypto)
    
    with open("all_strings.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_strings))
    
    with open("crypto_keys.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(crypto_findings))
    
    print("\n🎉 تمام شد!")
    print(f"   تعداد کل رشته‌ها: {len(all_strings):,}")
    print(f"   موارد رمزنگاری: {len(crypto_findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("استفاده: python extract_slipnet.py <آدرس_APK>")
        sys.exit(1)
    main(sys.argv[1])
