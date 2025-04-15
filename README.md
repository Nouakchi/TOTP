# 🔐 TOTP Implementation (Based on HOTP)

This project implements a Time-based One-Time Password (TOTP) generator in Python. It is built on top of the HMAC-based One-Time Password (HOTP) algorithm, but replaces the simple counter with a moving factor derived from the current Unix time. This README provides a step-by-step explanation of the entire process, including secret key encoding, generating a time-based counter, converting that counter to bytes, computing the HMAC-SHA1, performing dynamic truncation, and ultimately extracting and formatting the OTP token. It also covers generating a provisioning URI and a QR code for easy configuration in OTP apps.

---

## Table of Contents

- [Overview](#overview)
- [Detailed Implementation Steps](#detailed-implementation-steps)
  - [1. Secret Key & Base32 Encoding](#1-secret-key--base32-encoding)
  - [2. Time-Based Counter Calculation](#2-time-based-counter-calculation)
  - [3. Counter to Bytes Conversion](#3-counter-to-bytes-conversion)
  - [4. HMAC-SHA1 Computation](#4-hmac-sha1-computation)
  - [5. Dynamic Truncation & Offset Extraction](#5-dynamic-truncation--offset-extraction)
  - [6. Extracting the 6-Digit TOTP Code](#6-extracting-the-6-digit-totp-code)
  - [7. Generating the Provisioning URI & QR Code](#7-generating-the-provisioning-uri--qr-code)
- [Token Lifespan](#token-lifespan)
- [Summary of Key Concepts](#summary-of-key-concepts)
- [Conclusion](#conclusion)

---

## Overview

TOTP (Time-based One-Time Password) is a common method for generating short-lived, secure tokens. Unlike HOTP, which uses a counter that increments on each use, TOTP leverages the current Unix time divided by a fixed time-step (typically 30 seconds). This time-based counter guarantees that the token changes at regular intervals, ensuring enhanced security.

---

## Detailed Implementation Steps

Below are the detailed steps of the code with comprehensive explanations for each segment.

### 1. Secret Key & Base32 Encoding

The secret key is a shared secret known to both the client and server. For compatibility with OTP applications, it must be encoded in Base32.

<!-- ```bash
key = "your secret key"
secret = base64.b32encode(key.encode())
``` -->
    Secret Key:
A predefined string ("othman.nouakchi@007") acts as the shared secret.

Base32 Encoding:
    Purpose: Base32 is used because it is case-insensitive and URL-safe.
    
    Usage: 
base64.b32encode() converts the secret into a Base32 format so that it is easily usable by OTP applications (like Google Authenticator).

    Note: 
When forming the provisioning URI, any trailing padding (=) can be removed.

### 2. Time-Based Counter Calculation

TOTP relies on the current time divided by a fixed period (usually 30 seconds) to generate a "counter" that changes in discrete time steps.

counter = int(time.time()) // 30

    Unix Time:
The time.time() function returns the current Unix epoch time in seconds.

    30-Second Window:
Dividing the Unix time by 30 gives the number of 30-second intervals that have elapsed since January 1, 1970.

    Example:
If time.time() returns 1713190024, then:

counter = 1713190024 // 30  ≈ 57106334

    Purpose: 
This integer counter is used as the moving factor in the HOTP algorithm.

### 3. Counter to Bytes Conversion

The calculated counter needs to be converted into an 8-byte array in big-endian format before it can be used with the HMAC function.

counter_bytes = struct.pack(">Q", counter)

    Big-Endian Format (>Q):

Q: Means packing a 64-bit unsigned integer.

">": Specifies big-endian byte order, meaning the most significant byte (MSB) comes first.

Significance: This is required by the HOTP standard (RFC 4226), ensuring consistent representation of the counter.

### 4. HMAC-SHA1 Computation

The HMAC-SHA1 algorithm is used to combine the secret key and the counter bytes to produce a hash that is later truncated to generate the OTP.

hash_mac = hmac.new(key.encode(), counter_bytes, hashlib.sha1).digest()

    HMAC:
HMAC stands for Hash-based Message Authentication Code. It is created by combining a key with the message (in this case, counter_bytes), using a cryptographic hash function (SHA1).

    SHA1 Algorithm:
Although SHA1 is considered weak for some purposes, it is still widely used in OTP algorithms.

    Output:
The digest() call generates a 20-byte binary hash that is used in the next step.

### 5. Dynamic Truncation & Offset Extraction

Dynamic truncation extracts a portion of the 20-byte HMAC output to form an integer, ensuring a variable starting point based on the HMAC’s last byte.

offset = hash_mac[-1] & 0x0F

    Offset Calculation:

The last byte of the hash_mac is used.

A bitwise AND with 0x0F extracts the lower 4 bits of that byte.

Range: This produces an offset between 0 and 15.

code = struct.unpack(">I", hash_mac[offset:offset+4])[0] & 0x7FFFFFFF

    Extracting 4 Bytes:
Using the computed offset, 4 consecutive bytes are taken from the hash_mac.

    Unpacking:
struct.unpack(">I", ...) converts these 4 bytes from big-endian format into a 32-bit integer.

    Bitmask with 0x7FFFFFFF:
This masks off the most significant bit, ensuring that the integer is a positive 31-bit number. This is done to avoid any potential sign issues.

### 6. Extracting the 6-Digit TOTP Code

The OTP is generated by taking the 31-bit integer from the previous step and reducing it modulo 10**6 to produce a 6-digit code.

token = code % (10 ** 6)
print(f"{token:06d}")

    Modulo Operation:
The % (10 ** 6) ensures that the resulting token is within the range 0 to 999999 (i.e., 6 digits).

    Formatting:
The formatted print statement f"{token:06d}" guarantees that the token is zero-padded to 6 digits if necessary.

### 7. Generating the Provisioning URI & QR Code

Provisioning URIs allow OTP apps to easily add your account using a QR code.
Provisioning URI

uri = (
    f"otpauth://totp/ft_otp:othman.nouakchi007@gmail.com"
    f"?secret={secret.decode('utf-8').rstrip('=')}"
    f"&issuer=othman"
    f"&algorithm=SHA1"
    f"&digits=6"
    f"&period=30"
)

    otpauth URI Scheme:
This standardized URI is used by OTP apps.

#### URI Components:

Type: totp

Label: ft_otp:exemple@gmail.com (can include issuer and account)

Parameters:

secret: The Base32 encoded secret (with trailing = removed for neatness).

issuer: The name of the service or organization (othman).

algorithm: The hash algorithm used (SHA1).

digits: The number of digits in the OTP (6).

period: The time step in seconds (30).

#### Generating a QR Code

qr = qrcode.QRCode()
qr.add_data(uri)
qr.make()

print("\nScan this QR Code with your Authenticator app:\n")
qr.print_ascii(invert=True)

    QR Code Creation:

The qrcode module constructs a QR code based on the provisioning URI.

    Displaying the QR Code:

The print_ascii(invert=True) method prints an ASCII representation of the QR code in the terminal.

        Usage: 
This QR code can be scanned by an OTP application (such as Google Authenticator) to automatically configure the token generator.

#### Token Lifespan

    Short-Lived Tokens:
TOTP tokens are valid for the duration of one time-step period (commonly 30 seconds). They change with every new interval, ensuring that the window for an attacker to reuse the token is extremely small.

    Long-Lived Tokens:
These are not part of the TOTP mechanism, but other systems such as OAuth or recovery tokens provide longer validity periods. TOTP is designed specifically for short-term, dynamic authentication.

#### Summary of Key Concepts
Concept	Explanation
HOTP	An algorithm that generates one-time passwords using a secret key and a counter.

TOTP	A specific form of HOTP that derives the counter from the current time divided by a fixed period.

HMAC-SHA1	A cryptographic function that combines the secret key and message (counter bytes) to produce a secure hash.

Base32 Encoding	A way of encoding binary data using 32 different characters, making it URL-safe and case-insensitive.

Big-Endian Packing	Packing data such that the most significant byte is stored first, ensuring consistency per RFC 4226.

Dynamic Truncation	A method to select a 4-byte segment from the HMAC result based on an offset derived from its last byte.

Bitmasking	Applying a bitwise AND (e.g., 0x7FFFFFFF) to ensure the extracted code is positive and fits within 31 bits.

Modulo Operation	Reducing the integer to a 6-digit value by taking the remainder after division by 10^6.

Provisioning URI & QR	A standardized URI and QR code format that allows OTP apps to easily import the token configuration.

#### Conclusion

This TOTP implementation demonstrates how to:

    Encode a Secret Key: 
Using Base32 to generate a user-friendly secret.

    Compute a Time-Based Counter: 
By using Unix time divided into fixed intervals (30 seconds).

    Convert the Counter to Bytes: 
Ensuring compliance with the HOTP standard by packing in big-endian order.

    Generate an HMAC-SHA1 Hash: 
Combining the secret key with the time-based counter.

    Apply Dynamic Truncation: 
Extracting a 4-byte segment from the hash using bitwise operations.

    Format the OTP: 
Extracting a 6-digit token from the integer result.

    Create a Provisioning URI and QR Code:
Enabling seamless integration with popular OTP applications.

By following these steps, you can generate secure, short-lived TOTP tokens suitable for two-factor authentication and other security-critical applications.

Happy coding!
