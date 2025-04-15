import time
import struct
import hmac
import hashlib
import base64
import qrcode

key = "your secret key here"
counter = int(time.time()) // 30

counter_bytes = struct.pack(">Q", counter)

hash_mac = hmac.new(key.encode(), counter_bytes, hashlib.sha1).digest()

offset = hash_mac[-1] & 0x0F

code = struct.unpack(">I", hash_mac[offset:offset+4])[0] & 0x7FFFFFFF;

token = code % (10 ** 6)

print(f"{token:06d}")

secret = base64.b32encode(key.encode())

# otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp&digits=6&period=30&algorithm=SHA1

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

print("\nScan this QR Code with your Authenticator app:\n")
qr.print_ascii(invert=True)  # Use print_ascii() or print_tty()
