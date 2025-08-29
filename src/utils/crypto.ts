import { bytesToBase64, base64ToBytes } from "../base64";


// AES anahtarı oluşturma
export async function generateAesKey(): Promise<CryptoKey> {
  return window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

// AES anahtarını Base64 string olarak dışa aktarma
export async function exportAesKey(key: CryptoKey): Promise<string> {
  const raw = await window.crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Base64 string'den AES anahtarı içe aktarma
export async function importAesKey(base64Key: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}

// AES ile şifreleme
export async function aesEncrypt(plaintext: string, key: CryptoKey): Promise<{iv: string, cipher: string}> {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  const encrypted = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );
  
  return {
    iv: bytesToBase64(iv),
    cipher: bytesToBase64(new Uint8Array(encrypted))
  };
}

// AES ile şifre çözme
export async function aesDecrypt(iv: string, cipher: string, key: CryptoKey): Promise<string> {
  const ivBytes = base64ToBytes(iv);
  const cipherBytes = base64ToBytes(cipher);
  
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM",: ivBytes },
    key,
    cipherBytes
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}

// SHA-256 hash
export async function sha256(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await window.crypto.subtle.digest("SHA-256", data);
  return bytesToBase64(new Uint8Array(hash));
}
