import streamlit as st
import hashlib
import time
import json
import os
import io 
import requests # Pinata (Uzak IPFS) ile iletişim için
from datetime import datetime

# --- GENEL SABİTLER ---

# Pinata API'sine erişim için Streamlit Secrets kullanılır
# Bu dosya, Streamlit Cloud'da kalıcılığı sağlamak için en son zincir CID'sini tutar.
# UYARI: Streamlit Cloud'da bu dosya silineceği için, bu kalıcılık
# sadece oturum süresince (veya kısa bir süre) geçerli olacaktır.
# Gerçek kalıcılık için harici bir DB gereklidir, ancak bu Pinata entegrasyonu projenin değerini artırır.
CID_FILE = "last_chain_cid.txt" 

# --- SINIF TANIMLARI ---

class Block:
    """Tek bir blok yapısını temsil eder."""
    def __init__(self, index, previous_hash, data):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Bloğun tüm verilerini kullanarak SHA-256 hash'ini hesaplar."""
        # Ensure that the dictionary includes all necessary attributes for hashing
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

# --- IPFS YÖNETİMİ VE KALICILIK FONKSİYONLARI (PINATA ÜZERİNDEN) ---

def save_chain_to_ipfs(chain):
    """Zinciri Pinata üzerinden IPFS'e yükler ve CID'yi döndürür."""
    
    # 1. Gerekli Pinata anahtarlarını Streamlit Secrets'ten çek
    try:
        PINATA_JWT = st.secrets["pinata"]["jwt"]
    except KeyError:
        st.error("❌ Pinata JWT anahtarı bulunamadı. Lütfen `.streamlit/secrets.toml` dosyasını kontrol edin.")
        return None

    # 2. JSON verisini hazırla
    serializable_chain = [block.__dict__ for block in chain]
    chain_json = json.dumps(serializable_chain, indent=4)
    
    # 3. Yükleme isteği için URL ve Başlıkları hazırla
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "Authorization": f"Bearer {PINATA_JWT}"
    }
    
    # Pinata'ya dosya yüklemek için "multipart/form-data" formatı gerekir.
    files = {
        "file": ("blockchain.json", chain_json, "application/json")
    }
    
    try:
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status() # HTTP hatası varsa istisna fırlat
        
        res_data = response.json()
        new_cid = res_data.get('IpfsHash')
        
        if not new_cid:
            st.error(f"❌ Pinata CID döndürmedi: {res_data.get('error', 'Bilinmeyen Hata')}")
            return None
        
        # 4. Yeni CID'yi yerel dosyaya kaydet (Streamlit'in geçici dosya sisteminde bile)
        with open(CID_FILE, 'w') as f:
            f.write(new_cid)
            
        return new_cid
        
    except requests.exceptions.HTTPError as err:
        st.error(f"❌ Pinata HTTP Hatası: {err}. JWT anahtarının geçerli olduğundan emin olun.")
        return None
    except Exception as e:
        st.error(f"❌ IPFS Yükleme sırasında bir hata oluştu: {e}")
        return None

def load_chain_from_ipfs():
    """Son CID'yi okur ve zinciri IPFS'ten geri yükler."""
    
    # Streamlit Cloud'da CID_FILE'ın kaybolması muhtemeldir.
    if not os.path.exists(CID_FILE):
        return None
        
    try:
        # 1. Kayıtlı CID'yi oku
        with open(CID_FILE, 'r') as f:
            last_cid = f.read().strip()
        
        if not last_cid:
            return None

        # 2. Veriyi Pinata Ağ Geçidi üzerinden çek
        gateway_url = f"https://gateway.pinata.cloud/ipfs/{last_cid}"
        response = requests.get(gateway_url, timeout=10) # 10 saniye zaman aşımı
        response.raise_for_status()
        
        raw_chain = response.json()
        
        # 3. JSON'dan Blok nesnelerine geri yükle
        restored_chain = []
        for block_data in raw_chain:
            block = Block(block_data['index'], block_data['previous_hash'], block_data['data'])
            block.timestamp = block_data['timestamp']
            block.hash = block_data['hash']
            block.nonce = block_data['nonce']
            restored_chain.append(block)
        
        st.info(f"💾 Zincir IPFS'ten geri yüklendi. Son CID: **{last_cid[:10]}...**")
        return restored_chain

    except requests.exceptions.HTTPError as err:
        st.warning(f"⚠️ IPFS Ağ Geçidi Hatası. CID doğru değil veya pinlenmemiş olabilir. Hata: {err}")
        # Bu durumda zincir sıfırlanacaktır.
        return None
    except Exception as e:
        st.warning(f"⚠️ Yükleme hatası. Yeni zincir başlatılıyor. Hata: {e}")
        return None

# --- BLOCKCHAIN SINIFI ---

class Blockchain:
    """Tüm blok zincirini yönetir."""
    def __init__(self):
        # Eğer session state'de zincir yoksa, IPFS'ten veya sıfırdan oluştur
        if 'chain' not in st.session_state:
            
            restored_chain = load_chain_from_ipfs()
            
            if restored_chain:
                st.session_state.chain = restored_chain
            else:
                # Dosya yoksa veya yüklenemezse, yeni listeyi oluştur ve Genesis'i çağır
                st.session_state.chain = []
                self.chain = st.session_state.chain # self.chain'i Genesis'ten önce tanımla
                self.create_genesis_block()
        
        # self.chain'i her zaman session state'e bağla
        self.chain = st.session_state.chain

    @property
    def last_block(self):
        """Zincirdeki son bloğu döndürür. Zincir boşsa None döndürür."""
        return self.chain[-1] if self.chain else None

    def new_block(self, data, previous_hash=None):
        """Zincire yeni bir blok ekler ve IPFS'e kaydeder."""
        
        # Güvenli previous_hash alımı
        if previous_hash is None and self.last_block:
            last_block_hash = self.last_block.hash
        else:
            last_block_hash = "0"
        
        block = Block(len(self.chain), last_block_hash, data) 
        
        block.nonce = int(time.time() * 1000) % 100000 
        block.hash = block.calculate_hash() 

        self.chain.append(block)
        
        # *** IPFS Kalıcılık Adımı ***
        new_cid = save_chain_to_ipfs(self.chain) 
        if new_cid:
             st.sidebar.success(f"IPFS'e kaydedildi. CID: {new_cid[:10]}...")
        
        return block

    def create_genesis_block(self):
        """Zincirin ilk bloğunu (Genesis Block) oluşturur."""
        genesis_block = self.new_block(data="Genesis Block", previous_hash="0")
        st.success("✨ Yeni bir Blockchain başlatıldı (IPFS'e kaydediliyor).")
        
    def is_chain_valid(self):
        """Zincirin geçerliliğini kontrol eder."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            if current_block.hash != current_block.calculate_hash():
                return False, f"Hata: Blok {current_block.index} hash'i geçersiz."
            
            if current_block.previous_hash != previous_block.hash:
                return False, f"Hata: Blok {current_block.index} önceki bloğa bağlı değil."
            
        return True, "Blockchain tamamen geçerlidir. Değişiklik yok."

# --- YARDIMCI VE HASHLEME FONKSİYONLARI ---

def hash_file(uploaded_file):
    """Yüklenen dosyanın SHA-256 hash'ini hesaplar."""
    hasher = hashlib.sha256()
    file_bytes = io.BytesIO(uploaded_file.getvalue())
    
    for chunk in iter(lambda: file_bytes.read(4096), b""):
        hasher.update(chunk)
    
    uploaded_file.seek(0)
    return hasher.hexdigest()

# --- ANA UYGULAMA YAPISI ---

st.set_page_config(page_title="IPFS Kalıcılıklı Blockchain", layout="wide")

# Blockchain örneğini oluştur
blockchain = Blockchain()

st.title("🔗 IPFS Kalıcılıklı Merkeziyetsiz Blockchain")
st.markdown("Veri zinciri, Pinata API'si üzerinden IPFS ağına kaydedilir.")
st.divider()

# --- BLOK EKLEME BÖLÜMÜ (Sidebar) ---
st.sidebar.header("📁 Yeni Blok Ekle (Pinata API Kullanılır)")
uploaded_file = st.sidebar.file_uploader(
    "Blok Zincirine Kayıt Edilecek Dosyayı Yükleyin", 
    type=None, 
    key="file_uploader"
)
user_note = st.sidebar.text_input("Bu kayıtla ilgili notunuz (isteğe bağlı):", max_chars=100)

if uploaded_file is not None:
    file_hash = hash_file(uploaded_file)
    
    block_data = {
        "Dosya Adı": uploaded_file.name,
        "Dosya Hash (SHA-256)": file_hash,
        "Ek Not": user_note if user_note else "Yok"
    }
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("**Oluşturulacak Blok Verisi:**")
    st.sidebar.json(block_data)
    
    if st.sidebar.button("Blok Zincirine Ekle ve IPFS'e Kaydet"):
        prev_hash = blockchain.last_block.hash if blockchain.last_block else "0"
            
        new_block = blockchain.new_block(
            data=block_data,
            previous_hash=prev_hash
        )
        st.success(f"🎉 **{uploaded_file.name}** dosyası blok zincirine başarıyla eklendi!")
        st.balloons()
        st.rerun()

# --- ZİNCİRİ GÖRÜNTÜLEME BÖLÜMÜ (Main Content) ---

st.header(f"⛓️ Blok Zinciri ({len(blockchain.chain)} Blok)")

is_valid, message = blockchain.is_chain_valid()
if is_valid:
    st.success(f"Durum: {message}")
else:
    st.error(f"Durum: 🚨 {message} 🚨")

for block in reversed(blockchain.chain):
    with st.expander(f"Blok #{block.index} - Hash: {block.hash[:15]}...", expanded=block.index == len(blockchain.chain) - 1 and len(blockchain.chain) > 1):
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Blok Bilgileri")
            st.markdown(f"**Index:** `{block.index}`")
            st.markdown(f"**Zaman Damgası:** `{datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S')}`")
            st.markdown(f"**Nonce:** `{block.nonce}`")
            st.markdown(f"**Önceki Hash:** `{block.previous_hash}`")
        
        with col2:
            st.subheader("Dosya Verisi (Payload)")
            if isinstance(block.data, dict):
                 st.json(block.data)
            else:
                 st.write(block.data)

        st.markdown(f"**Bloğun Kendi Hash'i:**")
        st.code(block.hash)

# --- CID YÖNETİMİ ---

st.sidebar.markdown("---")
st.sidebar.header("IPFS Kalıcılık Durumu")

if os.path.exists(CID_FILE):
    try:
        with open(CID_FILE, 'r') as f:
            last_cid = f.read().strip()
            st.sidebar.info(f"Son CID (Ağ Adresi): `{last_cid[:10]}...`")
            st.sidebar.link_button("IPFS Ağ Geçidinde Görüntüle", f"https://gateway.pinata.cloud/ipfs/{last_cid}")
    except:
        st.sidebar.error("CID dosyası okunamıyor.")
else:
    st.sidebar.warning("Henüz bir CID kaydedilmemiş. İlk yüklemeden sonra görünecektir.")

if st.sidebar.button("🚨 CID Dosyasını Sil (Sıfırla)"):
    try:
        os.remove(CID_FILE)
        st.session_state.chain = []
        st.sidebar.success("CID dosyası silindi. Uygulama bir sonraki yenilemede sıfırdan başlayacak.")
        st.rerun()
    except Exception as e:
        st.sidebar.error(f"Dosya silinirken hata: {e}")
```
eof

---

## 🛠️ Kod Dışı Yapılması Gerekenler (Dağıtım İçin Zorunlu)

Streamlit Cloud'da bu uygulamanın Pinata API'sine bağlanabilmesi için aşağıdaki iki adımı kesinlikle yapmalısınız:

### Adım 1: Gereksinim Dosyası Oluşturma

Proje klasörünüzde **`requirements.txt`** adında bir dosya oluşturun ve içine şu kütüphaneleri ekleyin:

**`requirements.txt`**
```
streamlit
requests
```

### Adım 2: Pinata Anahtarlarını Streamlit Secrets'e Ekleme

Hassas API anahtarlarınızı doğrudan koda yazmak yerine, Streamlit'in güvenli mekanizması olan `secrets.toml` dosyasını kullanmalısınız.

1.  Projenizin kök dizininde **`.streamlit`** adında bir klasör oluşturun.
2.  Bu klasörün içine **`secrets.toml`** adında bir dosya oluşturun.
3.  Pinata hesabınızdan aldığınız **JWT** (JSON Web Token) anahtarını aşağıdaki formatta bu dosyaya ekleyin:

**`.streamlit/secrets.toml`**
```toml
[pinata]
# SİZİN PINATA JWT TOKEN'INIZ BURAYA GELMELİ.
# JWT, Pinata API ile kimlik doğrulaması yapmanın en güvenli yoludur.
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtY... (Devamı)"