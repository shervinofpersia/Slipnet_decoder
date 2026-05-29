import requests
import zipfile
import os
import re
import sys
from pathlib import Path

def download_apk(url, output="slipnet.apk"):
    print(f"📥 دانلود APK از: {url}")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    with open(output, 'wb') as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print("✅ دانلود کامل شد")
    return output

def extract_so_files(apk_path, extract_dir="extracted"):
    print("📦 استخراج فایل‌های .so ...")
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

def advanced_search(strings):
    findings = []
    # الگوهای مختلف کلید
    patterns = [
        r'\b[a-fA-F0-9]{64}\b',           # 32-byte hex
        r'[A-Za-z0-9+/=]{40,88}',         # Base64 مشکوک
        r'0x[a-fA-F0-9]{64}',             # 0x prefixed
    ]
    
    keywords = ['aes', 'gcm', 'encrypt', 'decrypt', 'iv', 'nonce', 'slipnet', 
                'secret', 'hardcode', 'hkdf', 'ntor', 'x25519', 'obfs', 'cipher',
                'key', 'master', 'private', 'public']

    for s in strings:
        s_lower = s.lower()
        if any(k in s_lower for k in keywords):
            findings.append(s)
            continue
        
        for pattern in patterns:
            matches = re.findall(pattern, s)
            for m in matches:
                findings.append(f"[POSSIBLE KEY] {m}  |  Original: {s[:150]}...")

    return findings

def main(apk_url):
    apk_file = "slipnet.apk"
    extract_dir = "extracted_so"
    
    download_apk(apk_url, apk_file)
    so_dir = extract_so_files(apk_file, extract_dir)
    
    all_strings = []
    crypto_findings = []
    important_files = ['libslipstream.so', 'libslipnet.so', 'libgojni.so', 'libobfs4proxy.so']
    
    for root, _, files in os.walk(so_dir):
        for file in files:
            if file.endswith('.so'):
                path = os.path.join(root, file)
                print(f"🔍 پردازش: {file}")
                
                strings = extract_strings(path)
                all_strings.extend(strings)
                
                crypto = advanced_search(strings)
                if crypto:
                    print(f"   🔑 {len(crypto)} مورد مشکوک در {file}")
                    crypto_findings.extend(crypto)
                
                # اولویت بالاتر برای فایل‌های مهم
                if any(imp in file for imp in important_files):
                    with open(f"{file}_strings.txt", "w", encoding="utf-8") as f:
                        f.write("\n".join(strings))
    
    # ذخیره خروجی نهایی
    with open("all_strings.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(all_strings))
    
    with open("crypto_keys.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(crypto_findings))
    
    with open("summary.txt", "w", encoding="utf-8") as f:
        f.write(f"تعداد کل رشته‌ها: {len(all_strings):,}\n")
        f.write(f"موارد رمزنگاری مشکوک: {len(crypto_findings)}\n")
        f.write(f"فایل‌های مهم پردازش شده: {len(important_files)}\n")
    
    print("\n🎉 تمام شد!")
    print("فایل‌های تولید شده: all_strings.txt , crypto_keys.txt , summary.txt")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("استفاده: python extract_slipnet.py <آدرس_APK>")
        sys.exit(1)
    main(sys.argv[1])
