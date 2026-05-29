import requests
import zipfile
import os
import re
import sys
from pathlib import Path

def download_apk(url, output="slipnet.apk"):
    print(f"📥 دانلود APK...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(output, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print("✅ دانلود کامل شد")
    return output

def extract_so_files(apk_path, extract_dir="extracted"):
    print("📦 استخراج تمام فایل‌های .so ...")
    os.makedirs(extract_dir, exist_ok=True)
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        for file in zip_ref.namelist():
            if file.endswith('.so'):
                zip_ref.extract(file, extract_dir)
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

def advanced_crypto_search(strings):
    results = []
    keywords = ['aes', 'gcm', 'key', 'encrypt', 'decrypt', 'iv', 'nonce', 'slipnet', 
                'secret', 'hardcode', 'hkdf', 'ntor', 'x25519', 'obfs', 'cipher']

    for s in strings:
        s_lower = s.lower()
        if any(k in s_lower for k in keywords):
            results.append(s)
            continue
        
        # جستجوی کلیدهای ۳۲ بایتی hex (64 کاراکتر)
        hex32 = re.findall(r'\b[a-fA-F0-9]{64}\b', s)
        if hex32:
            results.append(f"[POSSIBLE AES-256 KEY] {s}")
        
        # جستجوی Base64 مشکوک (طول تقریبی ۳۲ بایت)
        b64 = re.findall(r'[A-Za-z0-9+/=]{40,88}', s)
        for b in b64:
            if len(b) % 4 == 0 and ('=' in b or len(b) > 50):
                results.append(f"[POSSIBLE BASE64 KEY] {b}")

    return results

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
                
                crypto = advanced_crypto_search(strings)
                if crypto:
                    print(f"   🔑 {len(crypto)} مورد مشکوک پیدا شد")
                    crypto_findings.extend(crypto)
    
    # ذخیره خروجی
    with open("all_strings.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_strings))
    
    with open("crypto_keys.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(crypto_findings))
    
    with open("summary.txt", "w", encoding="utf-8") as f:
        f.write(f"تعداد کل رشته‌ها: {len(all_strings):,}\n")
        f.write(f"موارد مرتبط با رمزنگاری: {len(crypto_findings)}\n")
        f.write(f"فایل‌های .so پردازش شده: {len([f for r,d,fs in os.walk(so_dir) for f in fs if f.endswith('.so')])}\n")
    
    print("\n🎉 تمام شد!")
    print(f"   کل رشته‌ها → all_strings.txt")
    print(f"   یافته‌های مهم → crypto_keys.txt")
    print(f"   خلاصه → summary.txt")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("استفاده: python extract_slipnet.py <آدرس_APK>")
        sys.exit(1)
    main(sys.argv[1])
