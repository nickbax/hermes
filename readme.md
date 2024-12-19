# Hermes-eth

Password-protected Ethereum message encryption with optional verification. Messages are encrypted using AES-256-GCM with keys derived from Ethereum wallet signatures and passwords.
It is loosely based on [EIP-5630](https://eips.ethereum.org/EIPS/eip-5630). 

⚠️ **WARNING**: This code is unaudited and likely includes vulnerabilities. It is provided as an example and should not be used in production.

## Motivation
We needed a simple way to send encrypted messages to an Ethereum address. Crypto users are already accustomed to storing private keys for their address.
We wanted a way for the recipient to be able to easily destroy all messages they received, without having to destroy their private key.
With this scheme, the recipient can store their passwords on paper or in a password manager and periodically rotate to a new password when old messages are no longer needed. 

We added an optional message hashing scheme which allows for verification of the sent message by a third party. 

## How It Works

1. **Key Generation**
    - The recipient enters their chosen password
    - Their wallet signs a special message: `Generate encryption key for: {password}`
    - The signature is hashed to create a deterministic private key
    - This private key generates the public key that senders will use
    
2. **Encryption**
   - Sender uses recipient's public key to encrypt a message
   - Uses AES-256-GCM with an ephemeral key for perfect forward secrecy
   - Messages are padded to standard sizes (64, 128, 256, 512, 1024, or 2048 bytes) to prevent length analysis
   - Optional: Can include a salted hash for message verification

3. **Decryption**
   - Recipient needs both their Ethereum wallet and original password to decrypt
   - If verification was enabled, recipient gets a salt they can reveal to prove message contents

4. **Verification (Optional)**
   - When enabled, recipient can prove message contents to third parties
   - Requires revealing the decrypted message and salt
   - Anyone can verify the message matches the original without needing any keys

## Security Properties

- Forward secrecy via ephemeral keys
- Two-factor security (requires both wallet and password)
- Messages padded to prevent length analysis
- Recipients can destroy passwords to make messages permanently unreadable while retaining Ethereum private key.
- Optional third party message verification using salted hashes



## Message Format

```typescript
{
  encryptedData: string;     // Hex-encoded encrypted data
  ephemeralPublicKey: string;// Public key for this message
  iv: string;               // AES-GCM initialization vector
  scheme: 'password';       // Encryption scheme identifier
  verificationHash?: string;// Optional: Hash for verification
  verificationEnabled?: boolean; // Optional: Whether verification is enabled
}
```

## Development

```bash
git clone https://github.com/nickbax/hermes.git
cd hermes
npm install
npm run dev
```

## Building for IPFS

```bash
npm run build
```

## License

MIT
