# Signal

This project implements a secure communication platform enabling encrypted and authenticated communication using modular cryptographic techniques like Diffie-Hellman key exchange, AES, and HMAC.

## Cryptographic Components

### Key Exchange
Key exchange is the process by which two parties establish a shared secret over an insecure channel. The Diffie-Hellman protocol facilitates this by allowing both parties to exchange public values derived from private keys and common group parameters. Using these values, each party computes the shared secret independently. This shared secret serves as the foundation for deriving encryption and authentication keys, ensuring secure communication without prior key agreement.

### Key Derivation
Key derivation involves securely generating cryptographic keys from a shared secret. The platform uses the HMAC-based Key Derivation Function (HKDF) to derive separate keys for encryption and authentication. HKDF extracts randomness from the shared secret and expands it into cryptographically strong, application-specific keys. This ensures that the keys are unique and resistant to brute force or cryptographic attacks.

### Secure Communication

#### Encryption
Encryption ensures that messages remain confidential during transmission. The platform employs the Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC) mode. AES encrypts data in fixed-size blocks using a symmetric key, while CBC mode introduces randomness through initialization vectors (IVs), making identical plaintext blocks produce different ciphertexts. This mitigates patterns in the encrypted data.

#### Authentication
Authentication guarantees the integrity and authenticity of transmitted messages. By generating a cryptographic tag using the Hash-based Message Authentication Code (HMAC), the sender ensures that any modification to the message will be detectable. The recipient can verify the tag using the shared key, confirming that the message originated from a trusted source and has not been tampered with.

### Diffie-Hellman Ratchet
The Diffie-Hellman ratchet mechanism enhances security by periodically updating cryptographic keys. After each key exchange, a new shared secret is derived, which in turn generates fresh encryption and authentication keys. This practice ensures forward secrecy, meaning that even if a current key is compromised, past communications remain secure. The ratcheting process continuously evolves the cryptographic state, limiting the impact of potential breaches.

<img width="816" alt="Screenshot 2024-12-21 at 11 40 17 AM" src="https://github.com/user-attachments/assets/48043707-f54d-4e45-bbe1-58f6d3190492" />

### Message Integrity
An important aspect of communication is message integrity: we want to be sure that our
messages haven’t been tampered with in transit. A MAC (Message Authentication
Code) is one way of cryptographically ensuring message integrity. MAC generation
takes in a shared secret key and a message and outputs a tag for the message. MAC
verification takes in the shared secret key, a message, a MAC tag, and outputs “Verified”
(or some value to indicate so) if and only if the MAC tag is valid for the given message.
Otherwise, it rejects the tag, indicating that the value has been tampered with or that the
MAC tag was generated incorrectly. It must be computationally hard for an adversary
without the secret key to generate a valid MAC tag for any message (otherwise, this
wouldn’t be secure). The MAC tag that is computed on some value can be thought of
as a signature but with symmetric keys. In this project, we use HMAC (Hashed
Message Authentication Code), a widely used MAC algorithm.

## Usage

1. Build the project using `make`.
2. Run the client using `./client [mode] [host] [port]`. The mode can either be `connect` or `listen`, the host is the peer address (which is required for `connect`), and the port is the connection or listening port.

## Relevant Files
- `src/drivers/crypto_driver.cxx`: Cryptographic functions
- `src/pkg/client.cxx`: Key exchange and communication logic
- `include/crypto_driver.h`: Cryptographic prototypes
- `include/client.h`: Client logic prototypes
- `main.cxx`: Application entry point
