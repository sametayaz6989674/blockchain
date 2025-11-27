import streamlit as st
import hashlib
import time
import json
import os
import io 
import requests 
from datetime import datetime

# --- GENEL SABİTLER ---
# Streamlit Cloud'da geçici olarak zincirin son CID'sini tutacak dosya adı.
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
        # Hash hesaplaması için gerekli tüm özellikleri içerir
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        # JSON'a çevirip encode ediyoruz
        block_string = json.dumps(block_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

# --- IPFS YÖNETİMİ VE KALICILIK FONKSİYONLARI (PINATA ÜZERİNDEN) ---

def get_pinata_jwt():
    """Streamlit Secrets'ten Pinata JWT'yi güvenli bir şekilde çeker."""
    try:
        # Streamlit, bu anahtarı otomatik olarak secrets.toml dosyasından çeker.
        return st.secrets["pinata"]["jwt"]
    except KeyError:
        st.error("❌ Pinata JWT anahtarı bulunamadı. Lütfen `.streamlit/secrets.toml` dosyasını kontrol edin.")
        return None

def save_chain_to_ipfs(chain):
    """Zinciri Pinata üzerinden IPFS'e yükler ve CID'yi döndürür."""
    
    PINATA_JWT = get_pinata_jwt()
    if not PINATA_JWT:
        return None

    # Prepare chain data for serialization
    serializable_chain = [block.__dict__ for block in chain]
    chain_json = json.dumps(serializable_chain, indent=4)
    
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "Authorization": f"Bearer {PINATA_JWT}"
    }
    
    # Prepare data for multipart/form-data upload
    files = {
        "file": ("blockchain.json", chain_json.encode('utf-8'), "application/json")
    }
    
    try:
        response = requests.post(url, headers=headers, files=files, timeout=30)
        response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
        
        res_data = response.json()
        new_cid = res_data.get('IpfsHash')
        
        if not new_cid:
            st.error(f"❌ Pinata CID döndürmedi: {res_data.get('error', 'Bilinmeyen Hata')}")
            return None
        
        # Save the new CID to the temporary file for the next session/rerun
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
        response = requests.get(gateway_url, timeout=10) 
        response.raise_for_status() # Raise exception for bad status codes
        
        raw_chain = response.json()
        
        # 3. JSON'dan Blok nesnelerine geri yükle
        restored_chain = []
        for block_data in raw_chain:
            # Recreate block object
            block = Block(block_data['index'], block_data['previous_hash'], block_data['data'])
            # Restore original timestamp, hash, and nonce values
            block.timestamp = block_data['timestamp']
            block.hash = block_data['hash']
            block.nonce = block_data['nonce']
            restored_chain.append(block)
        
        st.info(f"💾 Zincir IPFS'ten geri yüklendi. Son CID: **{last_cid[:10]}...**")
        return restored_chain

    except requests.exceptions.HTTPError as err:
        st.warning(f"⚠️ IPFS Ağ Geçidi Hatası. CID doğru değil veya pinlenmemiş olabilir. Hata: {err}")
        return None
    except Exception as e:
        st.warning(f"⚠️ Yükleme hatası. Yeni zincir başlatılıyor. Hata: {e}")
        return None

# --- BLOCKCHAIN SINIFI ---

class Blockchain:
    """Tüm blok zincirini yönetir."""
    def __init__(self):
        # Use session_state to maintain the chain across reruns
        if 'chain' not in st.session_state:
            
            restored_chain = load_chain_from_ipfs()
            
            if restored_chain:
                st.session_state.chain = restored_chain
            else:
                # If restoration fails or it's the first run, initialize and create Genesis
                st.session_state.chain = []
                self.chain = st.session_state.chain 
                self.create_genesis_block()
        
        # Always link the instance variable to the session state
        self.chain = st.session_state.chain

    @property
    def last_block(self):
        """Zincirdeki son bloğu döndürür. Zincir boşsa None döndürür."""
        # Handles IndexError: list index out of range
        return self.chain[-1] if self.chain else None

    def new_block(self, data, previous_hash=None):
        """Zincire yeni bir blok ekler ve IPFS'e kaydeder."""
        
        # Securely determine the previous hash: use last block's hash or "0" for Genesis
        last_block_hash = self.last_block.hash if self.last_block else "0"
        
        block = Block(len(self.chain), last_block_hash, data) 
        
        # Set nonce and calculate hash
        block.nonce = int(time.time() * 1000) % 100000 
        block.hash = block.calculate_hash() 

        self.chain.append(block)
        
        # IPFS Persistence Step
        new_cid = save_chain_to_ipfs(self.chain) 
        if new_cid:
             st.sidebar.success(f"IPFS'e kaydedildi. CID: {new_cid[:10]}...")
        
        return block

    def create_genesis_block(self):
        """Creates the first block of the chain (Genesis Block)."""
        genesis_block = self.new_block(data="Genesis Block", previous_hash="0")
        st.success("✨ Yeni bir Blockchain başlatıldı (IPFS'e kaydediliyor).")
        
    def is_chain_valid(self):
        """Checks the validity of the entire chain."""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]

            # 1. Check if the block's hash is correctly calculated
            if current_block.hash != current_block.calculate_hash():
                return False, f"Hata: Blok {current_block.index} hash'i geçersiz."
            
            # 2. Check if the block correctly links to the previous hash
            if current_block.previous_hash != previous_block.hash:
                return False, f"Hata: Blok {current_block.index} önceki bloğa bağlı değil."
            
        return True, "Blockchain tamamen geçerlidir. Değişiklik yok."

# --- HELPER AND HASHING FUNCTIONS ---

def hash_file(uploaded_file):
    """Calculates the SHA-256 hash of the uploaded file."""
    hasher = hashlib.sha256()
    file_bytes = io.BytesIO(uploaded_file.getvalue())
    
    # Read file in chunks to handle large files
    for chunk in iter(lambda: file_bytes.read(4096), b""):
        hasher.update(chunk)
    
    uploaded_file.seek(0) # Reset file pointer for further processing
    return hasher.hexdigest()

# --- MAIN APPLICATION STRUCTURE ---

st.set_page_config(page_title="IPFS Kalıcılıklı Blockchain", layout="wide")

# Blockchain instance is created, which handles loading from IPFS
blockchain = Blockchain()

st.title("🔗 IPFS Kalıcılıklı Merkeziyetsiz Blockchain")
st.markdown("Veri zinciri, Pinata API'si üzerinden IPFS ağına kaydedilir.")
st.divider()

# --- BLOCK ADDITION SECTION (Sidebar) ---
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
        
        # Call new_block without explicit previous_hash, as the method handles it securely
        new_block = blockchain.new_block(
            data=block_data
        )
        st.success(f"🎉 **{uploaded_file.name}** dosyası blok zincirine başarıyla eklendi!")
        st.balloons()
        st.rerun()

# --- CHAIN DISPLAY SECTION (Main Content) ---

st.header(f"⛓️ Blok Zinciri ({len(blockchain.chain)} Blok)")

is_valid, message = blockchain.is_chain_valid()
if is_valid:
    st.success(f"Durum: {message}")
else:
    st.error(f"Durum: 🚨 {message} 🚨")

# Display blocks in reverse order (newest first)
for block in reversed(blockchain.chain):
    # Expanded only for the latest block (if there is more than one block)
    is_latest = block.index == len(blockchain.chain) - 1 and len(blockchain.chain) > 1
    with st.expander(f"Blok #{block.index} - Hash: {block.hash[:15]}...", expanded=is_latest):
        
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

# --- CID MANAGEMENT ---

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
        if os.path.exists(CID_FILE):
             os.remove(CID_FILE)
        # Reset session state chain to ensure fresh start
        st.session_state.chain = []
        st.sidebar.success("CID dosyası silindi. Uygulama sıfırdan başlatılacak.")
        st.rerun()
    except Exception as e:
        st.sidebar.error(f"Dosya silinirken hata: {e}")
