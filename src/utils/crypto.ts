// src/utils/crypto.ts

// ---------- Helpers ----------
const enc = new TextEncoder();
const dec = new TextDecoder();

export const toB64 = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  return btoa(String.fromCharCode(...bytes));
};
export const fromB64 = (b64: string) =>
  Uint8Array.from(atob(b64), c => c.charCodeAt(0));
export const toHex = (buf: ArrayBuffer | Uint8Array) =>
  [...(buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf)]
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");

// ---------- SHA-256 ----------
export async function sha256(text: string): Promise<string> {
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return toHex(hash);
}

// ---------- AES-GCM (PBKDF2 ile parola bazlı) ----------
async function deriveAesKeyFromPassword(password: string, salt: Uint8Array) {
  const material = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", iterations: 100_000, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function aesEncrypt(
  text: string,
  password: string,
  opts?: { saltB64?: string; ivB64?: string }
) {
  const salt = opts?.saltB64 ? fromB64(opts.saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const iv   = opts?.ivB64   ? fromB64(opts.ivB64)   : crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveAesKeyFromPassword(password, salt);
  const ct   = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
  return { ciphertext: toB64(ct), salt: toB64(salt), iv: toB64(iv) };
}

export async function aesDecrypt(
  payload: { ciphertext: string; salt: string; iv: string },
  password: string
) {
  const salt = fromB64(payload.salt);
  const iv   = fromB64(payload.iv);
  const key  = await deriveAesKeyFromPassword(password, salt);
  const ct   = fromB64(payload.ciphertext);
  const pt   = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return dec.decode(pt);
}

// ---------- AES-GCM (raw key generate/export/import) ----------
export async function generateAesKey(length: 128 | 192 | 256 = 256): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length }, true, ["encrypt","decrypt"]);
}
export async function exportAesKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return toB64(raw); // base64 raw key
}
export async function importAesKey(keyB64: string): Promise<CryptoKey> {
  const raw = fromB64(keyB64);
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt","decrypt"]);
}

// ---------- RSA-OAEP (SHA-256) ----------
const wrapPem = (base64: string, header: string) => {
  const lines = base64.match(/.{1,64}/g)?.join("\n") ?? base64;
  return `-----BEGIN ${header}-----\n${lines}\n-----END ${header}-----`;
};
const stripPem = (pem: string) =>
  pem.replace(/-----BEGIN [^-]+-----/g, "")
     .replace(/-----END [^-]+-----/g, "")
     .replace(/\s+/g, "");

export async function generateRsaKeyPair(modulusLength: 2048 | 4096 = 4096) {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function exportRsaPublicKey(publicKey: CryptoKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return wrapPem(toB64(spki), "PUBLIC KEY");
}

export async function exportRsaPrivateKey(privateKey: CryptoKey) {
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privateKey);
  return wrapPem(toB64(pkcs8), "PRIVATE KEY");
}

export async function importRsaPublicKey(pem: string) {
  const der = fromB64(stripPem(pem));
  return crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}

export async function importRsaPrivateKey(pem: string) {
  const der = fromB64(stripPem(pem));
  return crypto.subtle.importKey("pkcs8", der, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}

export async function rsaEncrypt(plainText: string, publicKey: CryptoKey) {
  const buf = enc.encode(plainText);
  // Not: RSA-OAEP tek seferde sınırlı veri şifreler (4096-bit için ~446 byte).
  const ct = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, buf);
  return toB64(ct);
}

export async function rsaDecrypt(ciphertextB64: string, privateKey: CryptoKey) {
  const ct = fromB64(ciphertextB64);
  const pt = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, ct);
  return dec.decode(pt);
}
// --- AES-CBC (parola bazlı) ---
export async function aesCbcEncrypt(
  text: string,
  password: string,
  opts?: { saltB64?: string; ivB64?: string } // iv 16 byte
) {
  const salt: Uint8Array = opts?.saltB64 ? fromB64(opts.saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const iv:   Uint8Array = opts?.ivB64   ? fromB64(opts.ivB64)   : crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveAesKeyFromPassword(password, salt);
  const ct  = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, new TextEncoder().encode(text));
  return { ciphertext: toB64(ct), iv: toB64(iv), salt: toB64(salt) };
}

export async function aesCbcDecrypt(
  payload: { ciphertext: string; iv: string; salt: string },
  password: string
) {
  const salt = fromB64(payload.salt);
  const iv   = fromB64(payload.iv); // 16 byte
  const key  = await deriveAesKeyFromPassword(password, salt);
  const ct   = fromB64(payload.ciphertext);
  const pt   = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ct);
  return new TextDecoder().decode(pt);
}

// --- AES-CTR (parola bazlı) ---
export async function aesCtrEncrypt(
  text: string,
  password: string,
  opts?: { saltB64?: string; ivB64?: string; length?: number } // counter=iv, genelde 16 byte
) {
  const salt: Uint8Array = opts?.saltB64 ? fromB64(opts.saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const iv:   Uint8Array = opts?.ivB64   ? fromB64(opts.ivB64)   : crypto.getRandomValues(new Uint8Array(16));
  const len = opts?.length ?? 64; // counter bit length
  const key = await deriveAesKeyFromPassword(password, salt);
  const ct  = await crypto.subtle.encrypt({ name: "AES-CTR", counter: iv, length: len }, key, new TextEncoder().encode(text));
  return { ciphertext: toB64(ct), iv: toB64(iv), salt: toB64(salt) };
}

export async function aesCtrDecrypt(
  payload: { ciphertext: string; iv: string; salt: string },
  password: string,
  length: number = 64
) {
  const salt = fromB64(payload.salt);
  const iv   = fromB64(payload.iv);
  const key  = await deriveAesKeyFromPassword(password, salt);
  const ct   = fromB64(payload.ciphertext);
  const pt   = await crypto.subtle.decrypt({ name: "AES-CTR", counter: iv, length }, key, ct);
  return new TextDecoder().decode(pt);
}

