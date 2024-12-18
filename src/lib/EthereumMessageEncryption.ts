import { ethers } from 'ethers';

export class EthereumMessageEncryption {
  private readonly BLOCK_SIZES = [
    64,    // 64 bytes
    128,   // 128 bytes
    256,   // 256 bytes
    512,   // 512 bytes
    1024,  // 1KB
    2048   // 2KB max size
  ];

  constructor(private provider: ethers.Provider) {}

  private stripHexPrefix(hex: string): string {
    return hex.startsWith('0x') ? hex.slice(2) : hex;
  }

  private orderPublicKeys(key1: string, key2: string): [string, string] {
    const clean1 = this.stripHexPrefix(key1);
    const clean2 = this.stripHexPrefix(key2);
    return clean1 < clean2 ? [key1, key2] : [key2, key1];
  }

  private deriveSharedSecret(publicKey1: string, publicKey2: string): string {
    const [firstKey, secondKey] = this.orderPublicKeys(publicKey1, publicKey2);
    return ethers.keccak256(
      ethers.concat([
        ethers.getBytes('0x' + this.stripHexPrefix(firstKey)),
        ethers.getBytes('0x' + this.stripHexPrefix(secondKey))
      ])
    );
  }

  private getErrorMessage(error: unknown): string {
    if (error instanceof Error) return error.message;
    if (typeof error === 'string') return error;
    return 'Unknown error occurred';
  }

  private getTargetBlockSize(messageLength: number): number {
    for (const size of this.BLOCK_SIZES) {
      if (messageLength <= size - 9) {
        return size;
      }
    }
    throw new Error(`Message too long. Maximum size is ${this.BLOCK_SIZES[this.BLOCK_SIZES.length - 1] - 9} bytes`);
  }

  private padMessage(messageBytes: Uint8Array): Uint8Array {
    const originalLength = messageBytes.length;
    const targetSize = this.getTargetBlockSize(originalLength);
    
    const paddedMessage = new Uint8Array(targetSize);
    const lengthBytes = new Uint8Array(8);
    new DataView(lengthBytes.buffer).setBigUint64(0, BigInt(originalLength), true);
    
    paddedMessage[0] = 8;
    paddedMessage.set(lengthBytes, 1);
    paddedMessage.set(messageBytes, 9);
    
    const padding = crypto.getRandomValues(new Uint8Array(targetSize - originalLength - 9));
    paddedMessage.set(padding, originalLength + 9);
    
    return paddedMessage;
  }

  private unpadMessage(paddedMessage: Uint8Array): Uint8Array {
    const lengthBytesCount = paddedMessage[0];
    const lengthBytes = paddedMessage.slice(1, 1 + lengthBytesCount);
    const originalLength = Number(new DataView(lengthBytes.buffer).getBigUint64(0, true));
    return paddedMessage.slice(9, 9 + originalLength);
  }

  // Create message hash that will be revealed only when decrypted
  private async createMessageHash(message: Uint8Array, salt: Uint8Array): Promise<string> {
    const saltedMessage = new Uint8Array(message.length + salt.length);
    saltedMessage.set(message);
    saltedMessage.set(salt, message.length);
    return ethers.keccak256(saltedMessage);
  }

  // Public verification method when recipient chooses to reveal message and salt
  public async verifyMessage(message: string, salt: string, hash: string): Promise<boolean> {
    const messageBytes = ethers.toUtf8Bytes(message);
    const saltBytes = ethers.getBytes(salt);
    const saltedMessage = new Uint8Array(messageBytes.length + saltBytes.length);
    saltedMessage.set(messageBytes);
    saltedMessage.set(saltBytes, messageBytes.length);
    const computedHash = ethers.keccak256(saltedMessage);
    return computedHash === hash;
  }

  async generatePasswordBasedKey(password: string, signer: ethers.Signer) {
    try {
      const message = ethers.toUtf8Bytes(`Generate encryption key for: ${password}`);
      const signature = await signer.signMessage(message);
      const derivedKeyBytes = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(signature)));
      const signingKey = new ethers.SigningKey(derivedKeyBytes);
      const publicKey = signingKey.publicKey;
      return publicKey;
    } catch (error) {
      throw new Error(`Failed to generate password-based key: ${this.getErrorMessage(error)}`);
    }
  }


  async encryptMessage(message: string, recipientPublicKey: string, includeVerification = false) {
    try {
      // Convert message to bytes
      const messageBytes = ethers.toUtf8Bytes(message);
      
      let paddedMessage: Uint8Array;
      let verificationHash: string | undefined;
      let salt: Uint8Array | undefined;

      if (includeVerification) {
        // Generate random salt and hash for verification
        salt = crypto.getRandomValues(new Uint8Array(32));
        verificationHash = await this.createMessageHash(messageBytes, salt);

        // Combine message and salt
        const messageWithSalt = new Uint8Array(messageBytes.length + salt.length);
        messageWithSalt.set(messageBytes);
        messageWithSalt.set(salt, messageBytes.length);
        
        // Pad the combined message
        paddedMessage = this.padMessage(messageWithSalt);
      } else {
        // Just pad the message without salt
        paddedMessage = this.padMessage(messageBytes);
      }

      // Generate ephemeral key pair
      const ephemeralPrivateBytes = ethers.randomBytes(32);
      const ephemeralKey = new ethers.SigningKey(ephemeralPrivateBytes);
      const ephemeralPublicKey = ephemeralKey.publicKey;
      
      // Derive shared secret
      const sharedSecret = this.deriveSharedSecret(recipientPublicKey, ephemeralPublicKey);
      
      // Encrypt using AES-256-GCM
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const algorithm = { name: 'AES-GCM', iv: iv };
      
      // Use first 32 bytes of shared secret as key
      const keyBytes = ethers.getBytes(sharedSecret).slice(0, 32);
      
      const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        'AES-GCM',
        false,
        ['encrypt']
      );
      
      const encryptedData = await crypto.subtle.encrypt(
        algorithm,
        key,
        paddedMessage
      );

      // Only include verification fields if requested
      const result: any = {
        encryptedData: Buffer.from(encryptedData).toString('hex'),
        ephemeralPublicKey: ephemeralPublicKey,
        iv: Buffer.from(iv).toString('hex'),
        scheme: 'password',
      };

      if (includeVerification) {
        result.verificationHash = verificationHash;
        result.verificationEnabled = true;
      }
      
      return result;
    } catch (error) {
      throw new Error(`Failed to encrypt message: ${this.getErrorMessage(error)}`);
    }
  }

  async decryptMessage(
    encryptedMessage: {
      encryptedData: string;
      ephemeralPublicKey: string;
      iv: string;
      scheme: 'password';
      verificationHash?: string;
      verificationEnabled?: boolean;
    },
    signer: ethers.Signer,
    password: string
  ): Promise<{ message: string, salt?: string }> {
    try {
      const message = ethers.toUtf8Bytes(`Generate encryption key for: ${password}`);
      const signature = await signer.signMessage(message);
      const privateKeyBytes = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(signature)));
      const signingKey = new ethers.SigningKey(privateKeyBytes);
      
      const sharedSecret = this.deriveSharedSecret(signingKey.publicKey, encryptedMessage.ephemeralPublicKey);
      
      const algorithm = { 
        name: 'AES-GCM', 
        iv: new Uint8Array(Buffer.from(encryptedMessage.iv, 'hex'))
      };
      
      const keyBytes = ethers.getBytes(sharedSecret).slice(0, 32);
      
      const key = await crypto.subtle.importKey(
        'raw',
        keyBytes,
        'AES-GCM',
        false,
        ['decrypt']
      );
      
      const decryptedData = await crypto.subtle.decrypt(
        algorithm,
        key,
        Buffer.from(encryptedMessage.encryptedData, 'hex')
      );
      
      // Unpad and handle verification if enabled
      const unpaddedData = this.unpadMessage(new Uint8Array(decryptedData));
      
      if (encryptedMessage.verificationEnabled) {
        const messageBytes = unpaddedData.slice(0, -32);
        const salt = unpaddedData.slice(-32);
        const plaintext = ethers.toUtf8String(messageBytes);
        const saltHex = ethers.hexlify(salt);

        // Verify if hash is present
        if (encryptedMessage.verificationHash) {
          const computedHash = await this.createMessageHash(messageBytes, salt);
          if (computedHash !== encryptedMessage.verificationHash) {
            throw new Error('Message verification failed - hash mismatch');
          }
        }

        return {
          message: plaintext,
          salt: saltHex
        };
      } else {
        // No verification, just return the message
        return {
          message: ethers.toUtf8String(unpaddedData)
        };
      }
    } catch (error) {
      throw new Error(`Failed to decrypt message: ${this.getErrorMessage(error)}`);
    }
  }
}