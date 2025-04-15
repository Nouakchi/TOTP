# TOTP Authentication Implementation

## Introduction

This document provides a detailed explanation of the Time-based One-Time Password (TOTP) implementation based on HMAC-based One-Time Password (HOTP) algorithm. The implementation follows RFC 4226 (HOTP) and RFC 6238 (TOTP) specifications, providing secure authentication tokens that change at regular intervals.

## Table of Contents

- [Conceptual Overview](#conceptual-overview)
- [Secret Key Handling](#secret-key-handling)
- [Token Generation Process](#token-generation-process)
  - [Time-Based Moving Factor](#time-based-moving-factor)
  - [HMAC Generation](#hmac-generation)
  - [Dynamic Truncation](#dynamic-truncation)
  - [Token Extraction](#token-extraction)
- [URI Format for QR Code Generation](#uri-format-for-qr-code-generation)
- [Security Considerations](#security-considerations)
- [Implementation Notes](#implementation-notes)

## Conceptual Overview

TOTP (Time-based One-Time Password) is an extension of the HOTP (HMAC-based One-Time Password) algorithm that uses time as its moving factor instead of a counter. This creates a time-sensitive authentication token that automatically invalidates after a short period, typically 30 seconds.

The key differences between HOTP and TOTP:

| HOTP | TOTP |
|------|------|
| Uses a counter as moving factor | Uses time as moving factor |
| Counter must be synchronized between client and server | Time automatically synchronizes (with tolerance window) |
| Token valid until next counter increment | Token valid only for short time window (e.g., 30 seconds) |
| Long-lived tokens possible | Short-lived tokens only |

## Secret Key Handling

### Base32 Encoding

The secret key (e.g., "shared key secret") must be encoded into a format compatible with authenticator applications. We use Base32 encoding for this purpose:

1. Convert the secret key string to bytes (UTF-8 encoding)
2. Apply Base32 encoding to the bytes
3. Remove padding characters ('=') for URI compatibility

Base32 encoding is preferred over other encoding methods because:
- It uses only uppercase letters and numbers 2-7
- It avoids ambiguous characters (1, 0, O, I)
- It's URL-safe and compatible with most authenticator apps

## Token Generation Process

### Time-Based Moving Factor

TOTP uses Unix time divided by a time step (typically 30 seconds) as its moving factor:

1. Get current Unix timestamp (seconds since Jan 1, 1970 UTC)
2. Integer division by time step (30 seconds): `counter = int(time.time()) // 30`
3. Convert to 8-byte big-endian format: `counter_bytes = struct.pack(">Q", counter)`

This creates a value that changes every 30 seconds, serving as the moving factor for the HMAC operation. The time step value of 30 seconds represents a balance between security (shorter periods provide less time for attacks) and usability (longer periods reduce the frequency of token changes).

### HMAC Generation

The HMAC-SHA1 algorithm is used to generate a secure hash:

1. Key: UTF-8 encoded secret key
2. Message: 8-byte big-endian representation of the time counter
3. Algorithm: SHA-1 (produces a 20-byte/160-bit output)

```python
hash_mac = hmac.new(key.encode(), counter_bytes, hashlib.sha1).digest()
```

While SHA-1 is the standard algorithm for TOTP, modern implementations may use stronger algorithms like SHA-256 or SHA-512 for enhanced security.

### Dynamic Truncation

A dynamic truncation method is used to convert the HMAC output (20 bytes) into a 4-byte value:

1. Extract the offset value from the last byte of the HMAC output, using only the lower 4 bits:
   ```python
   offset = hash_mac[-1] & 0x0F  # Value between 0-15
   ```

2. Extract a 4-byte sequence starting at the offset position:
   ```python
   hash_mac[offset:offset+4]
   ```

3. Convert the 4-byte sequence to a 32-bit integer using big-endian format:
   ```python
   struct.unpack(">I", hash_mac[offset:offset+4])[0]
   ```

4. Apply a bitmask of 0x7FFFFFFF (clear the most significant bit):
   ```python
   & 0x7FFFFFFF
   ```
   This ensures a positive integer value by removing the sign bit.

The dynamic truncation process enhances security by using the HMAC's own output to determine which portion of itself to use, making the selection unpredictable.

### Token Extraction

The final step is to extract a human-readable token:

1. Apply modulo operation to get the desired number of digits (6 digits in this case):
   ```python
   token = code % (10 ** 6)  # Results in values from 0-999999
   ```

2. Format the token with leading zeros to ensure consistent length:
   ```python
   f"{token:06d}"  # Formats as 6 digits with leading zeros
   ```

This produces a 6-digit numeric token that changes every 30 seconds.

## URI Format for QR Code Generation

To enable easy setup in authenticator apps, a standard URI format is used:

```
otpauth://totp/ft_otp:othman.nouakchi007@gmail.com?secret=BASE32SECRET&issuer=othman&algorithm=SHA1&digits=6&period=30
```

This URI contains:
- Protocol identifier: `otpauth://totp/`
- Label: `ft_otp:exemple@gmail.com` (identifies the account)
- Parameters:
  - `secret`: Base32-encoded secret key (without padding characters)
  - `issuer`: The service or application name ("username")
  - `algorithm`: Hash algorithm used (SHA1)
  - `digits`: Number of digits in the token (6)
  - `period`: Time step in seconds (30)

The URI is then encoded into a QR code for easy scanning with authenticator apps.

## Security Considerations

1. **Secret Key Protection**: The secret key must be treated with the same level of security as passwords. It should never be transmitted over insecure channels or stored in plaintext.

2. **Time Synchronization**: TOTP relies on synchronized time between the server and client. Time drift can cause authentication failures, so a tolerance window (typically ±1 time step) is often implemented.

3. **Token Length**: The implementation uses 6-digit tokens, which provides a good balance between security and usability. Each token has a 1 in 1,000,000 chance of being guessed correctly.

4. **Brute Force Prevention**: Implement rate limiting and account lockout mechanisms to prevent brute force attacks.

## Implementation Notes

- The code uses Python's standard libraries along with the `qrcode` package for QR code generation.
- HMAC-SHA1 is used as specified in the RFCs, though more modern implementations might prefer SHA-256.
- The 30-second time step is a common standard, though different applications might use different values (60 seconds, etc.).
- The implementation follows the standard 6-digit token format used by most authenticator apps.

This implementation provides a secure, standards-compliant TOTP authentication system compatible with common authenticator applications like Google Authenticator, Authy, and others.
