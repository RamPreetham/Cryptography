**##AESUtil - AES-256 GCM Encryption in Java**

A simple and secure Java utility class for performing AES-256 encryption and decryption using `AES/GCM/NoPadding`.
This example uses Java's built-in cryptography libraries (`javax.crypto`) and supports authenticated encryption via **GCM mode**.


**Features**

- AES-256 encryption using GCM (secure and authenticated)
- Random IV generation for each encryption
- Base64-encoded encrypted string
- Supports encryption of personal and transaction details in banking/financial apps

---

**Dependencies**

- Java 8 or higher
- No external libraries required

---

**##How to Use**

#  Encrypt & Decrypt a Message

```java
String original = "AccountNo: 123456789 | Amount: $1000";

// Generate AES-256 key and IV
SecretKey key = AESUtil.generateKey();
byte[] iv = new byte[12];
new SecureRandom().nextBytes(iv);

// Encrypt the message
String encrypted = AESUtil.encrypt(original, key, iv);
System.out.println("Encrypted: " + encrypted);

// Decrypt the message
String decrypted = AESUtil.decrypt(encrypted, key, iv);
System.out.println("Decrypted: " + decrypted);
'''
