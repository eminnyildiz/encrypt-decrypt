import { useState } from "react";
import {
  // AES varyantları (crypto.ts’de ekledik)
  aesEncrypt, aesDecrypt,              // AES-GCM (parola bazlı)
  aesCbcEncrypt, aesCbcDecrypt,        // AES-CBC  (parola bazlı)
  aesCtrEncrypt, aesCtrDecrypt,        // AES-CTR  (parola bazlı)

  // RSA & Hash
  generateRsaKeyPair, exportRsaPublicKey, exportRsaPrivateKey,
  importRsaPublicKey, importRsaPrivateKey,
  rsaEncrypt, rsaDecrypt,
  sha256
} from "./utils/crypto";

type Tab = "aes" | "rsa" | "hash";
type Algo = "AES-GCM" | "AES-CBC" | "AES-CTR";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("aes");

  // --- AES ortak durumlar ---
  const [algo, setAlgo] = useState<Algo>("AES-GCM");
  const [password, setPassword] = useState("");

  // ŞİFRELE paneli
  const [plain, setPlain] = useState("");
  const [encCiphertext, setEncCiphertext] = useState("");
  const [encIv, setEncIv] = useState("");
  const [encSalt, setEncSalt] = useState("");

  // ÇÖZ paneli
  const [decCiphertext, setDecCiphertext] = useState("");
  const [decIv, setDecIv] = useState("");
  const [decSalt, setDecSalt] = useState("");
  const [decrypted, setDecrypted] = useState("");

  // --- RSA ---
  const [rsaPlainText, setRsaPlainText] = useState("");
  const [rsaCipherText, setRsaCipherText] = useState("");
  const [rsaPublicKey, setRsaPublicKey] = useState("");
  const [rsaPrivateKey, setRsaPrivateKey] = useState("");
  const [rsaDecryptedText, setRsaDecryptedText] = useState("");

  // --- HASH ---
  const [hashText, setHashText] = useState("");
  const [hash, setHash] = useState("");

  // AES fonksiyon haritaları (imzalar crypto.ts ile birebir)
  const encryptMap: Record<Algo, (t: string, p: string) => Promise<{ ciphertext: string; iv: string; salt: string }>> = {
    "AES-GCM": aesEncrypt,
    "AES-CBC": aesCbcEncrypt,
    "AES-CTR": aesCtrEncrypt
  };
  const decryptMap: Record<Algo, (pl: { ciphertext: string; iv: string; salt: string }, p: string) => Promise<string>> = {
    "AES-GCM": aesDecrypt,
    "AES-CBC": aesCbcDecrypt,
    "AES-CTR": aesCtrDecrypt
  };

  // --- AES handlers ---
  const handleEncrypt = async () => {
    if (!plain) return alert("⚠️ Metin gir.");
    if (!password) return alert("⚠️ Parola gir.");
    const { ciphertext, iv, salt } = await encryptMap[algo](plain, password);
    setEncCiphertext(ciphertext);
    setEncIv(iv);
    setEncSalt(salt);

    // Çöz paneline otomatik kopyala (kullanışlı)
    setDecCiphertext(ciphertext);
    setDecIv(iv);
    setDecSalt(salt);
  };

  const handleDecrypt = async () => {
    if (!decCiphertext || !decIv || !decSalt) return alert("⚠️ Çözülecek payload eksik.");
    if (!password) return alert("⚠️ Parola gir.");
    try {
      const text = await decryptMap[algo]({ ciphertext: decCiphertext, iv: decIv, salt: decSalt }, password);
      setDecrypted(text);
    } catch (e: any) {
      alert("❌ Çözme hatası: " + (e?.message ?? e));
    }
  };

  const generateRandomPassword = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const pw = Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
    setPassword(pw);
    alert("🔑 Rastgele parola oluşturuldu.");
  };

  // --- RSA handlers ---
  const handleGenerateRsaKeys = async () => {
    const keyPair = await generateRsaKeyPair();
    const publicKey = await exportRsaPublicKey(keyPair.publicKey);
    const privateKey = await exportRsaPrivateKey(keyPair.privateKey);
    setRsaPublicKey(publicKey);
    setRsaPrivateKey(privateKey);
    alert("🔑 RSA anahtar çifti oluşturuldu.");
  };

  const handleRsaEncrypt = async () => {
    if (!rsaPublicKey) return alert("⚠️ Public key gir/oluştur.");
    if (!rsaPlainText) return alert("⚠️ Metin gir.");
    try {
      const pub = await importRsaPublicKey(rsaPublicKey);
      const ct = await rsaEncrypt(rsaPlainText, pub);
      setRsaCipherText(ct);
    } catch (e: any) {
      alert("❌ RSA şifreleme hatası: " + (e?.message ?? e));
    }
  };

  const handleRsaDecrypt = async () => {
    if (!rsaPrivateKey || !rsaCipherText) return alert("⚠️ Private key ve ciphertext gir.");
    try {
      const priv = await importRsaPrivateKey(rsaPrivateKey);
      const pt = await rsaDecrypt(rsaCipherText, priv);
      setRsaDecryptedText(pt);
    } catch (e: any) {
      alert("❌ RSA çözme hatası: " + (e?.message ?? e));
    }
  };

  // --- HASH ---
  const handleHash = async () => {
    if (!hashText) return alert("⚠️ Hash edilecek metin gir.");
    const h = await sha256(hashText);
    setHash(h);
  };

  // --- UI yardımcı stiller ---
  const tabStyle = (isActive: boolean) => ({
    padding: "10px 20px",
    backgroundColor: isActive ? "#007bff" : "#f8f9fa",
    color: isActive ? "white" : "#333",
    border: "1px solid #dee2e6",
    cursor: "pointer",
    borderRadius: "8px 8px 0 0"
  });
  const box: React.CSSProperties = { border: "1px solid #dee2e6", padding: 16, borderRadius: 8 };
  // DEĞİŞİKLİK 1: containerStyle sabitini sildik.

  return (
    // DEĞİŞİKLİK 2: style={containerStyle} yerine className="main-container" kullandık
    <div className="main-container">
      <h1 style={{ textAlign: "center", color: "#333" }}>🔐 Şifreleme Araçları</h1>

      {/* Sekmeler */}
      <div style={{ display: "flex", gap: "2px", marginBottom: "20px" }}>
        <button style={tabStyle(activeTab === "aes")} onClick={() => setActiveTab("aes")}>🔒 Simetrik (AES)</button>
        <button style={tabStyle(activeTab === "rsa")} onClick={() => setActiveTab("rsa")}>🗝️ RSA</button>
        <button style={tabStyle(activeTab === "hash")} onClick={() => setActiveTab("hash")}>#️⃣ SHA-256</button>
      </div>

      <div style={{ border: "1px solid #dee2e6", padding: 20, borderRadius: "0 8px 8px 8px", width: "100%", maxWidth: "1000px" }}>
        {activeTab === "aes" && (
          <div>
            <h3>🔒 Simetrik Şifreleme</h3>
            <p style={{ color: "#666", fontSize: 14 }}>
              Algoritma seç → parola gir → solda şifrele, sağda çöz. Çıktılar base64’tür. GCM (IV=12B), CBC/CTR (IV=16B).
            </p>

            {/* Algoritma & Parola */}
            <div style={{ display: "flex", gap: 12, marginBottom: 12 }}>
              <select value={algo} onChange={(e) => setAlgo(e.target.value as Algo)}>
                <option value="AES-GCM">AES-GCM</option>
                <option value="AES-CBC">AES-CBC</option>
                <option value="AES-CTR">AES-CTR</option>
              </select>
              <input
                type="text"
                placeholder="Parola"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                style={{ flex: 1, padding: 8 }}
              />
              <button onClick={generateRandomPassword} style={{ padding: "8px 12px" }}>🎲 Rastgele Parola</button>
            </div>

            {/* İki panel: Şifrele / Çöz */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {/* Şifrele */}
              <section style={box}>
                <h4>Şifrele</h4>
                <textarea
                  placeholder="Şifrelenecek metin…"
                  value={plain}
                  onChange={(e) => setPlain(e.target.value)}
                  style={{ width: "100%", height: 100, marginBottom: 8 }}
                />
                <button onClick={handleEncrypt} style={{ padding: "8px 12px" }}>🔒 Şifrele</button>

                {encCiphertext && (
                  <>
                    <h5 style={{ marginTop: 12 }}>Ciphertext (base64)</h5>
                    <textarea readOnly value={encCiphertext} style={{ width: "100%", height: 70 }} />
                    <h5>IV (base64)</h5>
                    <input readOnly value={encIv} style={{ width: "100%" }} />
                    <h5>Salt (base64)</h5>
                    <input readOnly value={encSalt} style={{ width: "100%" }} />
                  </>
                )}
              </section>

              {/* Çöz */}
              <section style={box}>
                <h4>Çöz</h4>
                <label>Ciphertext (base64)</label>
                <textarea
                  value={decCiphertext}
                  onChange={(e) => setDecCiphertext(e.target.value)}
                  style={{ width: "100%", height: 70, marginBottom: 8 }}
                />
                <label>IV (base64)</label>
                <input
                  value={decIv}
                  onChange={(e) => setDecIv(e.target.value)}
                  style={{ width: "100%", marginBottom: 8 }}
                />
                <label>Salt (base64)</label>
                <input
                  value={decSalt}
                  onChange={(e) => setDecSalt(e.target.value)}
                  style={{ width: "100%", marginBottom: 8 }}
                />
                <button onClick={handleDecrypt} style={{ padding: "8px 12px" }}>🔓 Çöz</button>

                {decrypted && (
                  <>
                    <h5 style={{ marginTop: 12 }}>Düz Metin</h5>
                    <textarea readOnly value={decrypted} style={{ width: "100%", height: 70 }} />
                  </>
                )}
              </section>
            </div>
          </div>
        )}

        {activeTab === "rsa" && (
          <div>
            <h3>🗝️ RSA (OAEP/SHA-256)</h3>
            <p style={{ color: "#666", fontSize: 14 }}>Public key ile şifrele, private key ile çöz.</p>

            <button onClick={handleGenerateRsaKeys} style={{ padding: "8px 12px", marginBottom: 12 }}>
              🔑 RSA Anahtar Çifti Oluştur
            </button>

            <div style={{ marginBottom: 12 }}>
              <h4>🔓 Public Key</h4>
              <textarea
                value={rsaPublicKey}
                onChange={(e) => setRsaPublicKey(e.target.value)}
                style={{ width: "100%", height: 70, fontSize: 12 }}
                placeholder="Public key (PEM)"
              />
            </div>

            <div style={{ marginBottom: 12 }}>
              <h4>🔒 Private Key (Gizli)</h4>
              <textarea
                value={rsaPrivateKey}
                onChange={(e) => setRsaPrivateKey(e.target.value)}
                style={{ width: "100%", height: 70, fontSize: 12, backgroundColor: "#ffe6e6" }}
                placeholder="Private key (PEM)"
              />
            </div>

            <textarea
              placeholder="RSA ile şifrelenecek metin…"
              value={rsaPlainText}
              onChange={(e) => setRsaPlainText(e.target.value)}
              style={{ width: "100%", height: 90, marginBottom: 10 }}
            />

            <div style={{ marginBottom: 12 }}>
              <button onClick={handleRsaEncrypt} style={{ marginRight: 10, padding: "8px 12px" }}>🔒 RSA Şifrele</button>
              <button onClick={handleRsaDecrypt} style={{ padding: "8px 12px" }}>🔓 RSA Çöz</button>
            </div>

            {rsaCipherText && (
              <div style={{ marginBottom: 12 }}>
                <h4>📦 RSA Ciphertext (base64)</h4>
                <textarea readOnly value={rsaCipherText} style={{ width: "100%", height: 80 }} />
              </div>
            )}

            {rsaDecryptedText && (
              <div>
                <h4>✅ RSA Çözülmüş Metin</h4>
                <textarea readOnly value={rsaDecryptedText} style={{ width: "100%", height: 60 }} />
              </div>
            )}
          </div>
        )}

        {activeTab === "hash" && (
          <div>
            <h3>#️⃣ SHA-256 Hash</h3>
            <p style={{ color: "#666", fontSize: 14 }}>Tek yönlü hash. Aynı girdi → aynı çıktı; geri dönüşü yok.</p>

            <textarea
              placeholder="Hash edilecek metin…"
              value={hashText}
              onChange={(e) => setHashText(e.target.value)}
              style={{ width: "100%", height: 90, marginBottom: 10 }}
            />
            <button onClick={handleHash} style={{ padding: "8px 12px", marginBottom: 12 }}>
              #️⃣ SHA-256 Hash Oluştur
            </button>

            {hash && (
              <div>
                <h4>🔗 SHA-256 (hex)</h4>
                <input readOnly value={hash} style={{ width: "100%", fontFamily: "monospace" }} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}