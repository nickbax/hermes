'use client';

import React, { useState } from 'react';
import { ethers } from 'ethers';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Label } from '@/components/ui/label';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { Lock, Unlock, Copy, Key, Shield, Info, KeyRound, CheckCircle, Scale } from 'lucide-react';
import { EthereumMessageEncryption } from '@/lib/EthereumMessageEncryption';

export function MessageEncryptionUI() {
  // State for wallet connection
  const [account, setAccount] = useState('');
  const [signer, setSigner] = useState<ethers.Signer | null>(null);
  const [encryptor, setEncryptor] = useState<EthereumMessageEncryption | null>(null);
  
  // State for key generation and encryption
  const [password, setPassword] = useState('');
  const [publicKey, setPublicKey] = useState('');
  const [recipientPublicKey, setRecipientPublicKey] = useState('');
  const [messageToEncrypt, setMessageToEncrypt] = useState('');
  const [encryptedMessage, setEncryptedMessage] = useState<any>(null);
  const [includeVerification, setIncludeVerification] = useState(false);

  // State for decryption and verification
  const [decryptPassword, setDecryptPassword] = useState('');
  const [encryptedMessageInput, setEncryptedMessageInput] = useState('');
  const [decryptedMessage, setDecryptedMessage] = useState('');
  const [decryptedSalt, setDecryptedSalt] = useState('');
  const [verified, setVerified] = useState<boolean | null>(null);
  const [error, setError] = useState('');
  
  // state for arbiter verification
  const [verificationJson, setVerificationJson] = useState('');
  const [arbiterVerified, setArbiterVerified] = useState<boolean | null>(null);

  const connectWallet = async () => {
    try {
      if (!window.ethereum) {
        throw new Error('Please install MetaMask');
      }
      
      const provider = new ethers.BrowserProvider(window.ethereum);
      const newSigner = await provider.getSigner();
      const address = await newSigner.getAddress();
      
      setAccount(address);
      setSigner(newSigner);
      setEncryptor(new EthereumMessageEncryption(provider));
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to connect wallet');
    }
  };

  const generatePublicKey = async () => {
    try {
      if (!encryptor || !signer || !password) {
        throw new Error('Please connect wallet and enter a password');
      }
      
      const generatedKey = await encryptor.generatePasswordBasedKey(password, signer);
      setPublicKey(generatedKey);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to generate key');
    }
  };

  const encryptMessage = async () => {
    try {
      if (!encryptor || !recipientPublicKey || !messageToEncrypt) {
        throw new Error('Missing recipient public key or message');
      }
      
      const encrypted = await encryptor.encryptMessage(
        messageToEncrypt, 
        recipientPublicKey,
        includeVerification
      );
      setEncryptedMessage(encrypted);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to encrypt');
    }
  };
  const decryptMessage = async () => {
    try {
      setVerified(null);
      if (!encryptor || !signer || !encryptedMessageInput || !decryptPassword) {
        throw new Error('Missing required fields for decryption');
      }
      
      const parsedMessage = JSON.parse(encryptedMessageInput);
      const result = await encryptor.decryptMessage(
        parsedMessage,
        signer,
        decryptPassword
      );
      
      setDecryptedMessage(result.message);
      // Only set the salt if it exists, otherwise clear it
      setDecryptedSalt(result.salt || '');
      setError('');
    } catch (error) {
      console.error('Decryption error:', error);
      setError(error instanceof Error ? error.message : 'Failed to decrypt');
      setDecryptedMessage('');
      setDecryptedSalt('');
    }
  };

  const verifyMessageHash = async () => {
    try {
      if (!encryptor || !decryptedMessage || !decryptedSalt || !encryptedMessageInput) {
        throw new Error('Missing verification data');
      }
      
      const parsedMessage = JSON.parse(encryptedMessageInput);
      const isValid = await encryptor.verifyMessage(
        decryptedMessage,
        decryptedSalt,
        parsedMessage.verificationHash
      );
      
      setVerified(isValid);
      setError('');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to verify');
      setVerified(null);
    }
  };

  const verifyAsArbiter = async () => {
    try {
      if (!encryptor || !verificationJson) {
        throw new Error('Please provide verification data');
      }
  
      const verificationData = JSON.parse(verificationJson);
      if (!verificationData.message || !verificationData.salt || !verificationData.hash) {
        throw new Error('Invalid verification data format');
      }
  
      const isValid = await encryptor.verifyMessage(
        verificationData.message,
        verificationData.salt,
        verificationData.hash
      );
      
      setArbiterVerified(isValid);
      setError('');
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to verify');
      setArbiterVerified(null);
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-4 space-y-4">

      <Alert variant="destructive" className="mb-4">
        <AlertDescription className="flex items-center gap-2">
          <span role="img" aria-label="warning">⚠️</span>
          <span>WARNING: This code is unaudited and likely includes vulnerabilities. It is provided as an example and should not be used in production</span>
          <span role="img" aria-label="warning">⚠️</span>
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5" />
            Password-Protected Message Encryption
            <TooltipProvider>
              <Tooltip>
                <TooltipTrigger asChild>
                  <Info className="h-4 w-4 cursor-help" />
                </TooltipTrigger>
                <TooltipContent className="max-w-sm">
                  <p>This system uses your Ethereum wallet combined with a password for enhanced security. 
                  Messages can only be decrypted with both the correct wallet and password.
                  Recipient should destroy their password when they no longer need access to the message.</p>
                </TooltipContent>
              </Tooltip>
            </TooltipProvider>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {!account ? (
            <div className="flex items-center gap-2">
              <Button onClick={connectWallet}>
                Connect Wallet
              </Button>
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="h-4 w-4 cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p>Connect your Ethereum wallet (like MetaMask) to start encrypting and decrypting messages.</p>
                  </TooltipContent>
                </Tooltip>
              </TooltipProvider>
            </div>
          ) : (
            <Alert>
              <AlertDescription>
                Connected: {account}
              </AlertDescription>
            </Alert>
          )}
          {error && (
            <Alert variant="destructive" className="mt-2">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {account && (
        <Tabs defaultValue="generate" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="generate">Generate Keys</TabsTrigger>
            <TabsTrigger value="encrypt">Send Message</TabsTrigger>
            <TabsTrigger value="arbiter">Arbiter Verification</TabsTrigger>
          </TabsList>
          
          <TabsContent value="generate" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <KeyRound className="w-5 h-5" />
                  Generate Public Key
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="genPassword">Encryption Password</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="genPassword"
                      type="password"
                      placeholder="Enter a strong password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Info className="h-4 w-4 cursor-help" />
                        </TooltipTrigger>
                        <TooltipContent>
                          <p>Choose a strong password. If your private key is compromised, an attacker will still need your password to decrypt messages you received.
                            Store your password securely. It is impossible to recover if you lose it.</p>
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </div>
                </div>

                <Button onClick={generatePublicKey}>
                  <Key className="w-4 h-4 mr-2" />
                  Generate Public Key
                </Button>

                {publicKey && (
                  <Alert>
                    <AlertDescription className="space-y-2">
                      <div className="font-mono text-sm break-all">{publicKey}</div>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full"
                        onClick={() => navigator.clipboard.writeText(publicKey)}
                      >
                        <Copy className="w-4 h-4 mr-2" />
                        Copy Public Key
                      </Button>
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Unlock className="w-5 h-5" />
                  Decrypt & Verify Messages
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="decryptPassword">Decryption Password</Label>
                  <Input
                    id="decryptPassword"
                    type="password"
                    placeholder="Enter your decryption password"
                    value={decryptPassword}
                    onChange={(e) => setDecryptPassword(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="encryptedMessage">Encrypted Message</Label>
                  <Textarea
                    id="encryptedMessage"
                    placeholder="Paste encrypted message JSON"
                    value={encryptedMessageInput}
                    onChange={(e) => setEncryptedMessageInput(e.target.value)}
                    rows={6}
                  />
                </div>

                <Button onClick={decryptMessage}>
                  <Unlock className="w-4 h-4 mr-2" />
                  Decrypt Message
                </Button>

                {decryptedMessage && (
                  <div className="space-y-4">
                    <Alert>
                      <AlertDescription>
                        <div className="font-mono text-sm break-all">
                          {decryptedMessage}
                        </div>
                      </AlertDescription>
                    </Alert>
                    
                    <div className="space-y-2">
                      <Button 
                        onClick={verifyMessageHash}
                        variant="outline" 
                        className="w-full"
                      >
                        <CheckCircle className="w-4 h-4 mr-2" />
                        Verify Message Authenticity
                      </Button>
                      
                      {verified !== null && (
                        <Alert variant={verified ? "default" : "destructive"}>
                          <AlertDescription>
                            {verified 
                              ? "Message verified! Hash matches the original encrypted content." 
                              : "Verification failed! Message may have been tampered with."}
                          </AlertDescription>
                        </Alert>
                      )}
                      
                      {verified && (
                        <div className="space-y-2">
                          <Alert>
                            <AlertDescription className="space-y-2">
                              <p className="font-semibold">Verification Data:</p>
                              <pre className="whitespace-pre-wrap break-all bg-secondary p-2 rounded-md font-mono text-sm">
                                {JSON.stringify(
                                  {
                                    message: decryptedMessage,
                                    salt: decryptedSalt,
                                    hash: JSON.parse(encryptedMessageInput).verificationHash
                                  },
                                  null,
                                  2
                                )}
                              </pre>
                              <Button
                                variant="outline"
                                size="sm"
                                className="w-full"
                                onClick={() => {
                                  const data = {
                                    message: decryptedMessage,
                                    salt: decryptedSalt,
                                    hash: JSON.parse(encryptedMessageInput).verificationHash
                                  };
                                  navigator.clipboard.writeText(JSON.stringify(data, null, 2));
                                }}
                              >
                                <Copy className="w-4 h-4 mr-2" />
                                Copy Verification Data
                              </Button>
                            </AlertDescription>
                          </Alert>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="encrypt" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Lock className="w-5 h-5" />
                  Send Encrypted Message
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="recipientKey">Recipient's Public Key</Label>
                  <Input
                    id="recipientKey"
                    placeholder="Paste recipient's public key"
                    value={recipientPublicKey}
                    onChange={(e) => setRecipientPublicKey(e.target.value)}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="message">Message</Label>
                  <Textarea
                    id="message"
                    placeholder="Enter message to encrypt"
                    value={messageToEncrypt}
                    onChange={(e) => setMessageToEncrypt(e.target.value)}
                    rows={4}
                  />
                </div>

                <div className="flex items-center gap-2">
                  <label className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      checked={includeVerification}
                      onChange={(e) => setIncludeVerification(e.target.checked)}
                      className="h-4 w-4 rounded border-gray-300"
                    />
                    <span>Enable Message Verification</span>
                  </label>
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Info className="h-4 w-4 cursor-help" />
                      </TooltipTrigger>
                      <TooltipContent>
                        <p>When enabled, the recipient can prove to others what message you sent them. 
                        They'll need to reveal the decrypted message to do this.</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </div>

                <Button onClick={encryptMessage}>
                  <Lock className="w-4 h-4 mr-2" />
                  Encrypt Message
                </Button>

                {encryptedMessage && (
                  <Alert>
                    <AlertDescription className="space-y-2">
                      <pre className="whitespace-pre-wrap break-all bg-secondary p-2 rounded-md font-mono text-sm">
                        {JSON.stringify(encryptedMessage, null, 2)}
                      </pre>
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full"
                        onClick={() => navigator.clipboard.writeText(
                          JSON.stringify(encryptedMessage)
                        )}
                      >
                        <Copy className="w-4 h-4 mr-2" />
                        Copy Encrypted Message
                      </Button>
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          </TabsContent>
          <TabsContent value="arbiter">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Scale className="w-5 h-5" />
                  Arbiter Verification
                  <TooltipProvider>
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Info className="h-4 w-4 cursor-help" />
                      </TooltipTrigger>
                      <TooltipContent className="max-w-sm">
                        <p>Verify message authenticity using the original message, salt, and hash. 
                        No private key or password required.</p>
                      </TooltipContent>
                    </Tooltip>
                  </TooltipProvider>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="verifyJson">Verification Data</Label>
                <Textarea
                  id="verifyJson"
                  placeholder="Paste the verification JSON data"
                  value={verificationJson}
                  onChange={(e) => setVerificationJson(e.target.value)}
                  rows={6}
                />
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Info className="h-4 w-4 cursor-help" />
                    </TooltipTrigger>
                    <TooltipContent>
                      <p>Paste the complete verification data JSON provided by the message recipient.</p>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              </div>

              <Button 
                onClick={verifyAsArbiter} 
                className="w-full"
                variant="outline"
              >
                <CheckCircle className="w-4 h-4 mr-2" />
                Verify Message
              </Button>

                {arbiterVerified !== null && (
                  <Alert variant={arbiterVerified ? "default" : "destructive"}>
                    <AlertDescription className="flex items-center gap-2">
                      {arbiterVerified ? (
                        <>
                          <CheckCircle className="w-4 h-4" />
                          Message verified! The provided message and salt match the original hash.
                        </>
                      ) : (
                        "Verification failed! The message, salt, or hash may be incorrect."
                      )}
                    </AlertDescription>
                  </Alert>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
