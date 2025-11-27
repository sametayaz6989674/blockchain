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
IPFS_GATEWAYS = [
    "https://gateway.pinata.cloud/ipfs/",
    "https://cloudflare-ipfs.com/ipfs/",
    "https://ipfs.io/ipfs/",
    "https://dweb.link/ipfs/"
]

# --- SAYFA AYARLARI VE CSS TASARIMI ---
st.set_page_config(page_title="Blockchain Dosya Paylaşımı", layout="wide", page_icon="📂")

# Arka planı beyaz, yazıları koyu yapmak için CSS enjeksiyonu
st.markdown("""
<style>
    /* Ana arka plan */
    .stApp {
        background-color: #ffffff;
        color: #1f1f1f;
    }
    /* Input alanları ve kutular */
    .stTextInput > div > div > input, .stFileUploader {
        background-color: #f0f2f6;
        color: black;
    }
    /* Expander başlıkları */
    .streamlit-expanderHeader {
        background-color: #f8f9fa;
        color: #31333F;
        border-radius: 5px;
    }
    /* Butonlar */
    .stButton > button {
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

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

# --- YEDEKLİ AĞ GEÇİDİ İNDİRİCİSİ ---

def fetch_file_with_redundancy(file_cid):
    """Dosyayı indirmek için sırasıyla farklı IPFS ağ geçitlerini dener."""
    status_text = st.empty()
    status_text.info(f"🔄 Dosya aranıyor... (CID: `{file_cid[:10]}...`)")
    logs = [] 
    
    for gateway in IPFS_GATEWAYS:
        target_url = f"{gateway}{file_cid}"
        try:
            response = requests.get(target_url, timeout=15)
            if response.status_code == 200:
                status_text.success(f"✅ Dosya `{gateway}` üzerinden başarıyla çekildi!")
                time.sleep(1) # Kullanıcı başarı mesajını görsün
                status_text.empty() # Mesajı temizle
                return response.content
            else:
                logs.append(f"❌ {gateway}: HTTP {response.status_code}")
        except requests.exceptions.Timeout:
            logs.append(f"⏳ {gateway}: Zaman aşımı")
        except Exception as e:
            logs.append(f"⚠️ {gateway}: Hata")
            
    status_text.error("Dosya hiçbir ağ geçidinden çekilemedi.")
    with st.expander("Hata Detayları"):
        for log in logs: st.write(log)
    return None

def load_chain_from_ipfs():
    """Zinciri yüklerken de yedekli sistemi kullanır."""
    if not os.path.exists(CID_FILE): return None
    try:
        with open(CID_FILE, 'r') as f:
            last_cid = f.read().strip()
        if not last_cid: return None

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

# --- BLOCKCHAIN MANTIĞI ---

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

# --- ARAYÜZ (GÜNCELLENMİŞ TASARIM) ---

blockchain = Blockchain()

st.title("BLOCKCHAİN DOSYA PAYLAŞIMI")
st.markdown("""
Bu platform, **merkeziyetsiz ve güvenli** dosya paylaşımı sağlar. Yüklediğiniz veriler **Pinata** aracılığıyla IPFS ağına kalıcı olarak işlenir. 
Dosyalarınıza **açıklama ekleyebilir**, tamamen **anonim** bir şekilde paylaşım yapabilirsiniz. Kimliğiniz gizli kalır ve verileriniz değiştirilemez bir blok zinciri üzerinde saklanır.
""")
st.divider()

# Dosya Ekleme Bölümü
with st.container(border=True):
    col1, col2 = st.columns([3, 1])
    with col1:
        st.subheader("DOSYA EKLE")
        uploaded_file = st.file_uploader("Bir dosya seçin veya sürükleyin", type=None)
        user_note = st.text_input("Açıklama Ekle:", max_chars=100, placeholder="Dosya hakkında kısa bir bilgi...")
    
    if uploaded_file and col1.button("Blok Zincirine Kaydet", use_container_width=True):
        file_hash = hash_file(uploaded_file)
        with st.spinner("Dosya Pinata IPFS ağına yükleniyor..."):
            file_cid = upload_file_to_ipfs(uploaded_file, uploaded_file.name)
        
        if file_cid:
            new_block = blockchain.new_block({
                "file_name": uploaded_file.name,
                "file_hash": file_hash,
                "note": user_note if user_note else "Açıklama yok",
                "file_cid": file_cid 
            })
            st.toast("Dosya başarıyla blok zincirine eklendi!", icon="✅")
            st.rerun()

    with col2:
        st.metric("Toplam Paylaşım", len(blockchain.chain)-1 if len(blockchain.chain)>0 else 0)
        if os.path.exists(CID_FILE):
            st.success("IPFS Bağlantısı Aktif")

st.divider()
st.subheader("Dosya Geçmişi")

# Dosya Geçmişi Listeleme
for block in reversed(blockchain.chain):
    is_data = isinstance(block.data, dict) and block.index > 0
    
    if is_data:
        fname = block.data.get('file_name', 'Bilinmeyen Dosya')
        note = block.data.get('note', 'Yok')
        cid = block.data.get('file_cid', 'Yok')
        fhash = block.data.get('file_hash', 'Yok')
        date_str = datetime.fromtimestamp(block.timestamp).strftime('%d-%m-%Y %H:%M:%S')
        
        # Kart Görünümü (Expander)
        with st.expander(f"📄 {fname} (Eklenme: {date_str})", expanded=(block.index == len(blockchain.chain)-1)):
            
            c1, c2 = st.columns([2, 1])
            
            with c1:
                st.markdown(f"**📂 Dosya Adı:** {fname}")
                st.markdown(f"**📝 Açıklama:** {note}")
                st.markdown(f"**📅 Yüklenme Tarihi:** {date_str}")
                st.markdown(f"**🔗 CİD:** `{cid}`")
                
                # Teknik Detaylar (Gizlenebilir Alan)
                with st.expander("🛠️ Teknik Blok Detayları (Hash & Nonce)"):
                    st.code(f"HASH: {fhash}", language="text")
                    st.text(f"Blok Index: {block.index}")
                    st.text(f"Nonce: {block.nonce}")
                    st.text(f"Blok Hash: {block.hash}")
                    st.text(f"Önceki Hash: {block.previous_hash}")

            with c2:
                st.write("#### İndirme İşlemi")
                # --- YENİ İNDİRME MODELİ ---
                download_key = f"file_content_{block.index}"
                
                if st.button(f"⬇️ İndirmeyi Başlat", key=f"btn_{block.index}", use_container_width=True):
                    file_content = fetch_file_with_redundancy(cid)
                    if file_content is not None:
                        st.session_state[download_key] = file_content
                        st.rerun()
                    else:
                        if download_key in st.session_state:
                            del st.session_state[download_key]

                if download_key in st.session_state:
                    st.success("✅ Dosya hazır!")
                    st.download_button(
                        label=f"💾 Kaydet: {fname}",
                        data=st.session_state[download_key],
                        file_name=fname,
                        mime="application/octet-stream",
                        key=f"dl_{block.index}",
                        use_container_width=True
                    )
    
    elif block.index == 0:
        with st.container():
            st.caption(f"🏁 Başlangıç Bloğu (Genesis) - {datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
