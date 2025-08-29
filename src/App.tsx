import { useState } from "react";
import {
  sha256,
  aesEncrypt,
  aesDecrypt,
  generateAesKey,
  exportAesKey,
  importAesKey,
  generateRsaKeyPair,
  exportRsaPublicKey,
  exportRsaPrivateKey,
  importRsaPublicKey,
  importRsaPrivateKey,
  rsaEncrypt,
  rsaDecrypt
} from "./utils/crypto";

export default function App() {
  const [activeTab, setActiveTab] = useState("aes");
  
  // AES State'leri
  const [aesPlainText, setAesPlainText] = useState("");
  const [aesCipherText, setAesCipherText] = useState("");
  const [aesIv, setAesIv] = useState("");
  const [aesKeyBase64, setAesKeyBase64] = useState("");
  const [aesDecryptedText, setAesDecryptedText] = useState("");
  
  // RSA State'leri
  const [rsaPlainText, setRsaPlainText] = useState("");
  const [rsaCipherText, setRsaCipherText] = useState("");
  const [rsaPublicKey, setRsaPublicKey] = useState("");
  const [rsaPrivateKey, setRsaPrivateKey] = useState("");
  const [rsaDecryptedText, setRsaDecryptedText] = useState("");
  
  // Hash State
  const [hashText, setHashText] = useState("");
  const [hash, setHash] = useState("");

  // AES Fonksiyonları
  const handleGenerateAesKey = async () => {
    const key = await generateAesKey();
    const exported = await exportAesKey(key);
    setAesKeyBase64(exported);
    alert("🔑 AES anahtarı oluşturuldu!");
  };

  const handleAesEncrypt = async () => {
    if (!aesKeyBase64) return alert("⚠️ Önce AES anahtarı oluştur!");
    const key = await importAesKey(aesKeyBase64);
    const { iv, cipher } = await aesEncrypt(aesPlainText, key);
    setAesIv(iv);
    setAesCipherText(cipher);
  };

  const handleAesDecrypt = async () => {
    if (!aesKeyBase64 || !aesCipherText || !aesIv) return alert("⚠️ Eksik veri!");
    const key = await importAesKey(aesKeyBase64);
    const text = await aesDecrypt(aesIv, aesCipherText, key);
    setAesDecryptedText(text);
  };

  // RSA Fonksiyonları
  const handleGenerateRsaKeys = async () => {
    const keyPair = await generateRsaKeyPair();
    const publicKey = await exportRsaPublicKey(keyPair.publicKey);
    const privateKey = await exportRsaPrivateKey(keyPair.privateKey);
    setRsaPublicKey(publicKey);
    setRsaPrivateKey(privateKey);
    alert("🔑 RSA anahtar çifti oluşturuldu!");
  };

  const handleRsaEncrypt = async () => {
    if (!rsaPublicKey) return alert("⚠️ Önce RSA anahtarları oluştur!");
    if (!rsaPlainText) return alert("⚠️ Şifrelenecek metin gir!");
    try {
      const publicKey = await importRsaPublicKey(rsaPublicKey);
      const encrypted = await rsaEncrypt(rsaPlainText, publicKey);
      setRsaCipherText(encrypted);
    } catch (error) {
      alert("❌ Şifreleme hatası: " + error);
    }
  };

  const handleRsaDecrypt = async () => {
    if (!rsaPrivateKey || !rsaCipherText) return alert("⚠️ Eksik veri!");
    try {
      const privateKey = await importRsaPrivateKey(rsaPrivateKey);
      const decrypted = await rsaDecrypt(rsaCipherText, privateKey);
      setRsaDecryptedText(decrypted);
    } catch (error) {
      alert("❌ Şifre çözme hatası: " + error);
    }
  };

  // SHA-256 hash
  const handleHash = async () => {
    if (!hashText) return alert("⚠️ Hash edilecek metin gir!");
    const h = await sha256(hashText);
    setHash(h);
  };

  const tabStyle = (isActive: boolean) => ({
    padding: "10px 20px",
    backgroundColor: isActive ? "#007bff" : "#f8f9fa",
    color: isActive ? "white" : "#333",
    border: "1px solid #dee2e6",
    cursor: "pointer",
    borderRadius: "8px 8px 0 0"
  });

  const containerStyle = {
    padding: "20px",
    fontFamily: "Arial, sans-serif",
    maxWidth: "800px",
    margin: "0 auto"
  };

  return (
    <div style={containerStyle}>
      <h1 style={{ textAlign: "center", color: "#333" }}>🔐 Şifreleme Araçları</h1>
      
      {/* Tab Navigation */}
      <div style={{ display: "flex", gap: "2px", marginBottom: "20px" }}>
        <button 
          style={tabStyle(activeTab === "aes")}
          onClick={() => setActiveTab("aes")}
        >
          🔒 AES-GCM (Simetrik)
        </button>
        <button 
          style={tabStyle(activeTab === "rsa")}
          onClick={() => setActiveTab("rsa")}
        >
          🗝️ RSA (Asimetrik)
        </button>
        <button 
          style={tabStyle(activeTab === "hash")}
          onClick={() => setActiveTab("hash")}
        >
          #️⃣ SHA-256 Hash
        </button>
      </div>

      {/* Tab Content */}
      <div style={{ border: "1px solid #dee2e6", padding: "20px", borderRadius: "0 8px 8px 8px" }}>
        
        {activeTab === "aes" && (
          <div>
            <h3>🔒 AES-GCM Şifreleme (Simetrik)</h3>
            <p style={{ color: "#666", fontSize: "14px" }}>Aynı anahtar hem şifreleme hem şifre çözme için kullanılır.</p>
            
            <div style={{ marginBottom: "15px" }}>
              <button onClick={handleGenerateAesKey} style={{ marginRight: "10px", padding: "8px 15px" }}>
                🔑 Anahtar Oluştur
              </button>
              <input
                type="text"
                placeholder="Base64 AES Anahtarı"
                value={aesKeyBase64}
                onChange={(e) => setAesKeyBase64(e.target.value)}
                style={{ width: "100%", padding: "8px", marginTop: "5px" }}
              />
            </div>

            <textarea
              placeholder="Şifrelenecek metin..."
              value={aesPlainText}
              onChange={(e) => setAesPlainText(e.target.value)}
              style={{ width: "100%", height: "80px", marginBottom: "10px" }}
            />

            <div style={{ marginBottom: "15px" }}>
              <button onClick={handleAesEncrypt} style={{ marginRight: "10px", padding: "8px 15px" }}>
                🔒 Şifrele
              </button>
              <button onClick={handleAesDecrypt} style={{ padding: "8px 15px" }}>
                🔓 Çöz
              </button>
            </div>

            {aesCipherText && (
              <div style={{ marginBottom: "15px" }}>
                <h4>📦 Şifrelenmiş Veri:</h4>
                <textarea readOnly value={aesCipherText} style={{ width: "100%", height: "60px" }} />
              </div>
            )}

            {aesIv && (
              <div style={{ marginBottom: "15px" }}>
                <h4>🎲 IV (Initialization Vector):</h4>
                <input readOnly value={aesIv} style={{ width: "100%" }} />
              </div>
            )}

            {aesDecryptedText && (
              <div>
                <h4>✅ Çözülmüş Metin:</h4>
                <textarea readOnly value={aesDecryptedText} style={{ width: "100%", height: "60px" }} />
              </div>
            )}
          </div>
        )}

        {activeTab === "rsa" && (
          <div>
            <h3>🗝️ RSA Şifreleme (Asimetrik)</h3>
            <p style={{ color: "#666", fontSize: "14px" }}>
              Public key ile şifrelenir, private key ile çözülür. Anahtar çifti gerekir.
            </p>
            
            <button onClick={handleGenerateRsaKeys} style={{ padding: "8px 15px", marginBottom: "15px" }}>
              🔑 RSA Anahtar Çifti Oluştur
            </button>

            <div style={{ marginBottom: "15px" }}>
              <h4>🔓 Public Key (Şifreleme için):</h4>
              <textarea 
                value={rsaPublicKey}
                onChange={(e) => setRsaPublicKey(e.target.value)}
                style={{ width: "100%", height: "60px", fontSize: "12px" }}
                placeholder="Public key buraya yapıştırılabilir..."
              />
            </div>

            <div style={{ marginBottom: "15px" }}>
              <h4>🔒 Private Key (Çözme için - GİZLİ!):</h4>
              <textarea 
                value={rsaPrivateKey}
                onChange={(e) => setRsaPrivateKey(e.target.value)}
                style={{ width: "100%", height: "60px", fontSize: "12px", backgroundColor: "#ffe6e6" }}
                placeholder="Private key buraya yapıştırılabilir..."
              />
            </div>

            <textarea
              placeholder="RSA ile şifrelenecek metin (max ~190 karakter)..."
              value={rsaPlainText}
              onChange={(e) => setRsaPlainText(e.target.value)}
              style={{ width: "100%", height: "80px", marginBottom: "10px" }}
            />

            <div style={{ marginBottom: "15px" }}>
              <button onClick={handleRsaEncrypt} style={{ marginRight: "10px", padding: "8px 15px" }}>
                🔒 RSA Şifrele
              </button>
              <button onClick={handleRsaDecrypt} style={{ padding: "8px 15px" }}>
                🔓 RSA Çöz
              </button>
            </div>

            {rsaCipherText && (
              <div style={{ marginBottom: "15px" }}>
                <h4>📦 RSA Şifrelenmiş Veri:</h4>
                <textarea readOnly value={rsaCipherText} style={{ width: "100%", height: "80px" }} />
              </div>
            )}

            {rsaDecryptedText && (
              <div>
                <h4>✅ RSA Çözülmüş Metin:</h4>
                <textarea readOnly value={rsaDecryptedText} style={{ width: "100%", height: "60px" }} />
              </div>
            )}
          </div>
        )}

        {activeTab === "hash" && (
          <div>
            <h3>#️⃣ SHA-256 Hash</h3>
            <p style={{ color: "#666", fontSize: "14px" }}>
              Tek yönlü hash fonksiyonu. Aynı metin her zaman aynı hash'i verir, geri çevrilemez.
            </p>
            
            <textarea
              placeholder="Hash edilecek metin..."
              value={hashText}
              onChange={(e) => setHashText(e.target.value)}
              style={{ width: "100%", height: "80px", marginBottom: "10px" }}
            />

            <button onClick={handleHash} style={{ padding: "8px 15px", marginBottom: "15px" }}>
              #️⃣ SHA-256 Hash Oluştur
            </button>

            {hash && (
              <div>
                <h4>🔗 SHA-256 Hash:</h4>
                <input readOnly value={hash} style={{ width: "100%", fontFamily: "monospace" }} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}