import streamlit as st
import hashlib
import time
import json
import os
import io 
import requests 
from datetime import datetime
from urllib.parse import quote 

# --- GENEL SABİTLER ---
CID_FILE = "last_chain_cid.txt" 
PINATA_GATEWAY_UPLOAD = "https://api.pinata.cloud/"

# İndirme için kullanılacak Yedekli Ağ Geçidi Listesi
# Kod, sırasıyla bunları deneyerek en hızlısını bulacaktır.
IPFS_GATEWAYS = [
    "https://gateway.pinata.cloud/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/"
]

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
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

# --- PINATA YÜKLEME FONKSİYONLARI ---

def get_pinata_jwt():
    try:
        return st.secrets["pinata"]["jwt"]
    except KeyError:
        st.error("❌ Pinata JWT anahtarı bulunamadı. Lütfen `.streamlit/secrets.toml` dosyasını kontrol edin.")
        return None

def upload_file_to_ipfs(uploaded_file, file_name):
    """Dosyayı Pinata'ya yükler (Klasörsüz - wrapWithDirectory: False)."""
    PINATA_JWT = get_pinata_jwt()
    if not PINATA_JWT: return None
        
    url = PINATA_GATEWAY_UPLOAD + "pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}"}
    
    # Klasöre sarmalamayı devre dışı bırak (Doğrudan dosya CID'si al)
    pinata_options = json.dumps({"pinataOptions": {"wrapWithDirectory": False}})

    files = {
        "file": (file_name, uploaded_file.getvalue(), uploaded_file.type),
        "pinataOptions": (None, pinata_options, "application/json") 
    }
    
    try:
        response = requests.post(url, headers=headers, files=files, timeout=120) 
        response.raise_for_status()
        return response.json().get('IpfsHash')
    except Exception as e:
        st.error(f"❌ Dosya Yükleme Hatası: {e}")
        return None

def save_chain_to_ipfs(chain):
    """Zinciri Pinata'ya yükler."""
    PINATA_JWT = get_pinata_jwt()
    if not PINATA_JWT: return None

    serializable_chain = [block.__dict__ for block in chain]
    chain_json = json.dumps(serializable_chain, indent=4)
    
    url = PINATA_GATEWAY_UPLOAD + "pinning/pinFileToIPFS"
    headers = {"Authorization": f"Bearer {PINATA_JWT}"}
    pinata_options = json.dumps({"pinataOptions": {"wrapWithDirectory": False}})
    
    files = {
        "file": ("blockchain.json", chain_json.encode('utf-8'), "application/json"),
        "pinataOptions": (None, pinata_options, "application/json") 
    }
    
    try:
        response = requests.post(url, headers=headers, files=files, timeout=30)
        response.raise_for_status() 
        new_cid = response.json().get('IpfsHash')
        
        if new_cid:
            with open(CID_FILE, 'w') as f:
                f.write(new_cid)
        return new_cid
    except Exception as e:
        st.error(f"❌ Zincir Yükleme Hatası: {e}")
        return None

# --- YENİ MODEL: YEDEKLİ AĞ GEÇİDİ İNDİRİCİSİ ---

# Cache kullanmıyoruz veya kısa tutuyoruz çünkü ağ durumları değişebilir.
# Hata durumunda cache'lemeyi önlemek için show_spinner=False kullanıyoruz.
def fetch_file_with_redundancy(file_cid):
    """
    Dosyayı indirmek için sırasıyla farklı IPFS ağ geçitlerini dener.
    İlk başarılı olanın içeriğini döndürür.
    """
    
    st.write(f"🔄 Dosya aranıyor... (CID: `{file_cid[:10]}...`)")
    
    logs = [] # Hata loglarını tutmak için
    
    for gateway in IPFS_GATEWAYS:
        target_url = f"{gateway}{file_cid}"
        try:
            # 10 saniye zaman aşımı ile dene
            response = requests.get(target_url, timeout=10)
            
            if response.status_code == 200:
                # Başarılı!
                st.success(f"✅ Dosya `{gateway}` üzerinden başarıyla çekildi!")
                return response.content
            else:
                logs.append(f"❌ {gateway}: HTTP {response.status_code}")
                
        except requests.exceptions.Timeout:
            logs.append(f"⏳ {gateway}: Zaman aşımı")
        except Exception as e:
            logs.append(f"⚠️ {gateway}: Hata ({str(e)[:50]}...)")
            
    # Eğer buraya geldiyse hiçbir ağ geçidi çalışmamıştır
    with st.expander("Detaylı Hata Raporu (Tüm Ağ Geçitleri Başarısız)"):
        for log in logs:
            st.write(log)
    
    st.error("Üzgünüz, dosya şu anda hiçbir genel IPFS ağ geçidinden çekilemiyor. Dosya henüz ağa yayılmamış olabilir.")
    return None

def load_chain_from_ipfs():
    """Zinciri yüklerken de yedekli sistemi kullanır."""
    if not os.path.exists(CID_FILE): return None
    try:
        with open(CID_FILE, 'r') as f:
            last_cid = f.read().strip()
        if not last_cid: return None

        # Yedekli indiriciyi kullan (ama UI mesajlarını gizle)
        # Basit bir requests döngüsü:
        raw_data = None
        for gateway in IPFS_GATEWAYS:
            try:
                resp = requests.get(f"{gateway}{last_cid}", timeout=5)
                if resp.status_code == 200:
                    raw_data = resp.json()
                    break
            except: continue
            
        if not raw_data: return None
        
        restored_chain = []
        for block_data in raw_data:
            data_content = block_data.get('data', None)
            block = Block(block_data['index'], block_data['previous_hash'], data_content)
            block.timestamp = block_data['timestamp']
            block.hash = block_data['hash']
            block.nonce = block_data['nonce']
            restored_chain.append(block)
        
        st.toast(f"Zincir güncellendi (CID: {last_cid[:6]}...)", icon="🔗")
        return restored_chain
    except: return None

# --- BLOCKCHAIN VE UI ---

class Blockchain:
    def __init__(self):
        if 'chain' not in st.session_state:
            restored_chain = load_chain_from_ipfs()
            if restored_chain:
                st.session_state.chain = restored_chain
            else:
                st.session_state.chain = []
                self.chain = st.session_state.chain 
                self.create_genesis_block()
        self.chain = st.session_state.chain

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def new_block(self, data):
        last_block_hash = self.last_block.hash if self.last_block else "0"
        block = Block(len(self.chain), last_block_hash, data) 
        block.nonce = int(time.time() * 1000) % 100000 
        block.hash = block.calculate_hash() 
        self.chain.append(block)
        save_chain_to_ipfs(self.chain) 
        return block

    def create_genesis_block(self):
        self.new_block(data={"message": "Genesis Block", "file_cid": None})
        
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            if current.hash != current.calculate_hash() or current.previous_hash != prev.hash:
                return False, f"Blok {current.index} hatası."
        return True, "Geçerli."

def hash_file(uploaded_file):
    hasher = hashlib.sha256()
    file_bytes = io.BytesIO(uploaded_file.getvalue())
    for chunk in iter(lambda: file_bytes.read(4096), b""):
        hasher.update(chunk)
    uploaded_file.seek(0)
    return hasher.hexdigest()

# --- ARAYÜZ ---

st.set_page_config(page_title="Multi-Gateway Blockchain", layout="wide")
blockchain = Blockchain()

st.title("🔗 Çoklu Ağ Geçidi Destekli Blockchain")
st.markdown("Veriler Pinata'ya yüklenir, indirme işlemi ise **en hızlı yanıt veren** IPFS ağ geçidinden yapılır.")
st.divider()

with st.container(border=True):
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("📁 Yeni Dosya Ekle")
        uploaded_file = st.file_uploader("Dosya Seç", type=None)
        user_note = st.text_input("Not:", max_chars=100)
    
    if uploaded_file and col1.button("Blok Ekle ve Kaydet", use_container_width=True):
        file_hash = hash_file(uploaded_file)
        with st.spinner("Dosya Pinata'ya yükleniyor..."):
            file_cid = upload_file_to_ipfs(uploaded_file, uploaded_file.name)
        
        if file_cid:
            new_block = blockchain.new_block({
                "file_name": uploaded_file.name,
                "file_hash": file_hash,
                "note": user_note,
                "file_cid": file_cid 
            })
            st.toast("Blok eklendi!")
            st.rerun()

    with col2:
        st.metric("Toplam Blok", len(blockchain.chain))
        if os.path.exists(CID_FILE):
            with open(CID_FILE, 'r') as f:
                st.caption(f"Zincir CID: {f.read().strip()[:10]}...")

st.divider()
st.subheader(f"Zincir Geçmişi")

for block in reversed(blockchain.chain):
    is_data = isinstance(block.data, dict) and block.index > 0
    title = f"Blok #{block.index}"
    if is_data: title += f" - {block.data.get('file_name')}"
    
    with st.expander(title, expanded=(block.index == len(blockchain.chain)-1)):
        c1, c2 = st.columns([1, 1])
        with c1:
            st.write(f"**Hash:** `{block.hash[:20]}...`")
            st.write(f"**Önceki:** `{block.previous_hash[:20]}...`")
            if is_data:
                st.json(block.data)
        
        with c2:
            if is_data:
                cid = block.data.get('file_cid')
                fname = block.data.get('file_name', 'dosya')
                st.info(f"📂 Dosya CID: `{cid}`")
                
                # --- YENİ İNDİRME MODELİ ---
                # Butona basılınca 'fetch_file_with_redundancy' çalışır.
                # Key parametresi her blok için benzersiz olmalı.
                if st.button(f"⬇️ İndirmeyi Başlat ({fname})", key=f"btn_{block.index}"):
                    file_content = fetch_file_with_redundancy(cid)
                    
                    if file_content:
                        # İçerik başarıyla çekildiyse indirme butonunu göster
                        # (Streamlit kısıtlaması: Otomatik indirme başlatılamaz, kullanıcı ikinci kez basmalı)
                        st.download_button(
                            label=f"✅ Hazır! Buraya Tıkla ve İndir",
                            data=file_content,
                            file_name=fname,
                            mime="application/octet-stream",
                            key=f"dl_{block.index}"
                        )
            elif block.index == 0:
                st.write("Genesis Blok")
