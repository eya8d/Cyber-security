from flask import Flask, request, jsonify
from flask_cors import CORS
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import struct
import os 

# إنشاء التطبيق
app = Flask(__name__)
CORS(app)

# توليد مفاتيح RSA
RSA_KEY = RSA.generate(1024)
RSA_PUBLIC_KEY = RSA_KEY.publickey().export_key()

# -------------------------------
# دالة توليد أرقام عشوائية باستخدام LCG
def lcg(seed):
    a, c, m = 1664525, 1013904223, 2 ** 31
    return (a * seed + c) % m

# -------------------------------
# توليد مفتاح AES باستخدام LCG
def aes_key_from_seed(seed):
    key_int = lcg(seed)
    key_bytes = struct.pack('>I', key_int)
    return key_bytes.ljust(16, b'\0')  # نحوله لـ 16 بايت

# -------------------------------
# SHA-1
def sha1_manual(text):
    # الخطوة 1: تحويل الحروف لقيم ASCII
    ascii_vals = [ord(c) for c in text]

    # الخطوة 2: تحويل ASCII إلى ثنائي 8 بت
    binary_vals = ''.join(format(x, '08b') for x in ascii_vals)

    # الخطوة 3: نضيف 1 في الآخر
    binary_vals += '1'

    # الخطوة 4: نكمل 0 لحد ما نوصل 448 بت
    while len(binary_vals) % 512 != 448:
        binary_vals += '0'

    # الخطوة 5: نضيف طول الرسالة الأصلي في 64 بت
    original_length = len(text) * 8
    binary_vals += format(original_length, '064b')

    # الخطوة 6: نقسمهم إلى كلمات كل واحدة 32 بت
    chunks = [binary_vals[i:i+32] for i in range(0, len(binary_vals), 32)]

    # الخطوة 7: نوسعهم لـ 80 كلمة
    for i in range(16, 80):
        w = int(chunks[i-3], 2) ^ int(chunks[i-8], 2) ^ int(chunks[i-14], 2) ^ int(chunks[i-16], 2)
        w = ((w << 1) | (w >> 31)) & 0xFFFFFFFF  # دوران لليسار
        chunks.append(format(w, '032b'))

    # الخطوة 8: القيم الابتدائية
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # الخطوة 9: التكرار 80 مرة
    for i in range(80):
        if 0 <= i <= 19:
            f = (h1 & h2) | ((~h1) & h3)
            k = 0x5A827999
        elif 20 <= i <= 39:
            f = h1 ^ h2 ^ h3
            k = 0x6ED9EBA1
        elif 40 <= i <= 59:
            f = (h1 & h2) | (h1 & h3) | (h2 & h3)
            k = 0x8F1BBCDC
        else:
            f = h1 ^ h2 ^ h3
            k = 0xCA62C1D6

        temp = ((h0 << 5 | h0 >> 27) + f + h4 + k + int(chunks[i], 2)) & 0xFFFFFFFF
        h4 = h3
        h3 = h2
        h2 = (h1 << 30 | h1 >> 2) & 0xFFFFFFFF
        h1 = h0
        h0 = temp

    # الخطوة 10: نضيف القيم على القيم الابتدائية
    h0 = (h0 + 0x67452301) & 0xFFFFFFFF
    h1 = (h1 + 0xEFCDAB89) & 0xFFFFFFFF
    h2 = (h2 + 0x98BADCFE) & 0xFFFFFFFF
    h3 = (h3 + 0x10325476) & 0xFFFFFFFF
    h4 = (h4 + 0xC3D2E1F0) & 0xFFFFFFFF

    digest = ''.join(format(x, '08x') for x in [h0, h1, h2, h3, h4])

    return {
        "ascii": ascii_vals,
        "binary": binary_vals[:64] + '...',
        "hash": digest
    }

# -------------------------------
# تشفير AES باستخدام CBC
def aes_encrypt_detailed(text):
    key = aes_key_from_seed(12345)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = text.encode() + b"\0" * (16 - len(text.encode()) % 16)
    encrypted = cipher.encrypt(padded_text)
    return {
        "key": b64encode(key).decode(),
        "iv": b64encode(iv).decode(),
        "padded_text": padded_text.decode('latin1'),
        "ciphertext": b64encode(encrypted).decode()
    }

# -------------------------------
# فك تشفير AES
def aes_decrypt_detailed(ciphertext, iv_b64):
    key = aes_key_from_seed(12345)
    iv = b64decode(iv_b64)
    encrypted = b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted).rstrip(b"\0")
    return {
        "key": b64encode(key).decode(),
        "iv": b64encode(iv).decode(),
        "decrypted_text": decrypted.decode()
    }

# -------------------------------
# تشفير RSA بالمفتاح العام
def rsa_encrypt_detailed(text):
    cipher = PKCS1_OAEP.new(RSA_KEY.publickey())
    encrypted = cipher.encrypt(text.encode())
    return {
        "public_key": RSA_PUBLIC_KEY.decode(),
        "ciphertext": b64encode(encrypted).decode()
    }

# -------------------------------
# فك تشفير RSA (ممكن نربطه بـ LCG لو حبينا)
def rsa_decrypt_detailed(cipher_b64):
    try:
        cipher = PKCS1_OAEP.new(RSA_KEY)
        decrypted = cipher.decrypt(b64decode(cipher_b64))
        return {"decrypted_text": decrypted.decode()}
    except Exception as e:
        return {"error": str(e)}

# -------------------------------
# نقطة النهاية بتستقبل الطلبات وتعالج النوع المطلوب
@app.route("/api", methods=["POST"])
def api():
    data = request.get_json()
    type_ = data.get("type")
    text = data.get("text")
    iv = data.get("iv", None)  # استلام الـ IV في حالة التشفير باستخدام AES
    result = {}

    try:
        if type_ == "sha1":
            result = sha1_manual(text)
        elif type_ == "aes_encrypt":
            result = aes_encrypt_detailed(text)
        elif type_ == "aes_decrypt":
            if iv:
                result = aes_decrypt_detailed(text, iv)
            else:
                result = {"error": "IV missing for AES decryption."}
        elif type_ == "rsa_encrypt":
            result = rsa_encrypt_detailed(text)
        elif type_ == "rsa_decrypt":
            result = rsa_decrypt_detailed(text)
        else:
            result = {"error": "نوع العملية غير صحيح"}
    except Exception as e:
        result = {"error": str(e)}

    return jsonify(result)

# -------------------------------
# تشغيل السيرفر على بورت 8000
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port, debug=True)