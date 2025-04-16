import os
import sys
import hmac
import time
import struct
import base64
import qrcode
import hashlib
from cryptography.fernet import Fernet

def totp_token(key):
    counter = int(time.time()) // 30

    counter_bytes = struct.pack(">Q", counter)

    hash_mac = hmac.new(key.encode(), counter_bytes, hashlib.sha1).digest()

    offset = hash_mac[-1] & 0x0F

    code = struct.unpack(">I", hash_mac[offset:offset+4])[0] & 0x7FFFFFFF

    token = code % (10 ** 6)

    print(f"TOTP Token:\n {token:06d}")

    secret = base64.b32encode(key.encode())

    uri = (
        f"otpauth://totp/ft_otp:exemple@gmail.com"
        f"?secret={secret.decode('utf-8').rstrip('=')}"
        f"&issuer=username"
        f"&algorithm=SHA1"
        f"&digits=6"
        f"&period=30"
    )

    print("\nProvisioning URI:")
    print(uri)

    # === Generate and print QR code in terminal ===
    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.make()

    print("\nScan this QR Code with your Authenticator app:")
    qr.print_ascii(invert=True)

def encode_key() -> bytes:
    hash_digest = hashlib.sha256("PFXXK4RAONSWG4TFOQQGWZLZEBUGK4TF".encode()).digest()
    return base64.urlsafe_b64encode(hash_digest)


def generate_otp_key(key_file):
    if not os.path.exists(key_file):
        print("Error: Key file does not exist.")
        return

    with open(key_file, "r") as f:
        hex_key = f.read().strip()

    if len(hex_key) < 64:
        print("Error: Key must be at least 64 hexadecimal characters.")
        return
    
    try:
        bytes.fromhex(hex_key)
    except ValueError:
        print("Error: Invalid hexadecimal key in file.")
        return

    key = encode_key()
    fernet = Fernet(key)
    token = fernet.encrypt(hex_key.encode())

    with open("ft_otp.key", "wb") as f:
        f.write(token)

    print("Key stored and encrypted in ft_otp.key.")

    

def generate_otp_token(key_file):
    if not os.path.exists(key_file):
        print("Error: Key file does not exist.")
        return
    
    with open(key_file, "rb") as f:
        encoded_key = f.read()

    key = encode_key()
    fernet = Fernet(key)
    
    try:
        token = fernet.decrypt(encoded_key).decode()
    except Exception:
        print("Error: Unable to decrypt the key. Wrong password?")
        sys.exit(1)

    totp_token(token)


def main():
    options = sys.argv

    if (len(options) < 3):
        print("Usage:")
        print("  -g <64_hex_key>    store encrypted otp key")
        print("  -k <key_file>       Decrypt key and generate TOTP")
        return

    if options[1] == "-g":
        generate_otp_key(options[2])
    elif options[1] == "-k":
        generate_otp_token(options[2])
    else:
        print("Invalid usage. Try -g <key> or -k <key>.")


if __name__ == "__main__":
    main()
