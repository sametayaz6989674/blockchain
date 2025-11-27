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
# Pinata Ağ Geçidi URL'si (İndirme için kullanılır)
PINATA_GATEWAY = "https://gateway.pinata.cloud/ipfs/"

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
        # Not: Eğer 'data' None ise, json.dumps hata vermez, ancak bu yapıda 'data' her zaman olmalıdır.
        # Yine de JSON'a dönüştürmeden önce kontrol eklemek güvenliği artırır.
        block_string = json.dumps(block_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

# --- IPFS YÖNETİMİ VE KALICILIK FONKSİYONLARI (PINATA ÜZERİNDEN) ---

def get_pinata_jwt():
    """Streamlit Secrets'ten Pinata JWT'yi güvenli bir şekilde çeker."""
    try:
        return st.secrets["pinata"]["jwt"]
    except KeyError:
        st.error("❌ Pinata JWT anahtarı bulunamadı. Lütfen `.streamlit/secrets.toml` dosyasını kontrol edin.")
        return None

def upload_file_to_ipfs(uploaded_file, file_name):
    """Yüklenen dosyayı Pinata üzerinden IPFS'e kaydeder ve CID'sini döndürür."""
    
    PINATA_JWT = get_pinata_jwt()
    if not PINATA_JWT:
        return None
        
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "Authorization": f"Bearer {PINATA_JWT}"
    }
    
    # Dosya içeriğini bellekte tut (Streamlit file_uploader objesinden)
    files = {
        "file": (file_name, uploaded_file.getvalue(), uploaded_file.type)
    }
    
    try:
        response = requests.post(url, headers=headers, files=files, timeout=60)
        response.raise_for_status() 
        
        res_data = response.json()
        file_cid = res_data.get('IpfsHash')
        
        if not file_cid:
            st.error(f"❌ Pinata dosya CID'si döndürmedi: {res_data.get('error', 'Bilinmeyen Hata')}")
            return None
        
        # st.success(f"✅ Dosya IPFS'e kaydedildi. CID: {file_cid[:10]}...")
        return file_cid
        
    except requests.exceptions.HTTPError as err:
        st.error(f"❌ Dosya Pinata HTTP Hatası: {err}. JWT anahtarının geçerli olduğundan emin olun.")
        return None
    except Exception as e:
        st.error(f"❌ Dosya Yükleme sırasında bir hata oluştu: {e}")
        return None

def save_chain_to_ipfs(chain):
    """Zinciri Pinata üzerinden IPFS'e yükler ve yeni zincir CID'sini döndürür."""
    
    PINATA_JWT = get_pinata_jwt()
    if not PINATA_JWT:
        return None

    serializable_chain = [block.__dict__ for block in chain]
    chain_json = json.dumps(serializable_chain, indent=4)
    
    url = "https://api.pinata.cloud/pinning/pinFileToIPFS"
    headers = {
        "Authorization": f"Bearer {PINATA_JWT}"
    }
    
    files = {
        "file": ("blockchain.json", chain_json.encode('utf-8'), "application/json")
    }
    
    try:
        response = requests.post(url, headers=headers, files=files, timeout=30)
        response.raise_for_status() 
        
        res_data = response.json()
        new_cid = res_data.get('IpfsHash')
        
        if not new_cid:
            st.error(f"❌ Pinata zincir CID'si döndürmedi: {res_data.get('error', 'Bilinmeyen Hata')}")
            return None
        
        # Yeni CID'yi geçici dosyaya kaydet
        with open(CID_FILE, 'w') as f:
            f.write(new_cid)
            
        return new_cid
        
    except requests.exceptions.HTTPError as err:
        st.error(f"❌ Pinata HTTP Hatası: {err}. JWT anahtarının geçerli olduğundan emin olun.")
        return None
    except Exception as e:
        st.error(f"❌ Zincir Yükleme sırasında bir hata oluştu: {e}")
        return None

def load_chain_from_ipfs():
    """Son CID'yi okur ve zinciri IPFS'ten geri yükler."""
    
    if not os.path.exists(CID_FILE):
        return None
        
    try:
        with open(CID_FILE, 'r') as f:
            last_cid = f.read().strip()
        
        if not last_cid:
            return None

        gateway_url = f"{PINATA_GATEWAY}{last_cid}"
        response = requests.get(gateway_url, timeout=10) 
        response.raise_for_status()
        
        raw_chain = response.json()
        
        restored_chain = []
        for block_data in raw_chain:
            # Geri yükleme sırasında data'nın None gelme ihtimaline karşı kontrol
            data_content = block_data.get('data', None)
            
            block = Block(block_data['index'], block_data['previous_hash'], data_content)
            block.timestamp = block_data['timestamp']
            block.hash = block_data['hash']
            block.nonce = block_data['nonce']
            restored_chain.append(block)
        
        st.info(f"💾 Zincir IPFS'ten geri yüklendi. Son CID: **{last_cid[:10]}...**")
        return restored_chain

    except Exception as e:
        st.warning(f"⚠️ Yükleme hatası. Yeni zincir başlatılıyor. Hata: {e}")
        return None

# --- BLOCKCHAIN SINIFI ---

class Blockchain:
    """Tüm blok zincirini yönetir."""
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
        """Zincirdeki son bloğu döndürür. Zincir boşsa None döndürür."""
        return self.chain[-1] if self.chain else None

    def new_block(self, data, previous_hash=None):
        """Zincire yeni bir blok ekler ve IPFS'e kaydeder."""
        
        last_block_hash = self.last_block.hash if self.last_block else "0"
        
        block = Block(len(self.chain), last_block_hash, data) 
        
        block.nonce = int(time.time() * 1000) % 100000 
        block.hash = block.calculate_hash() 

        self.chain.append(block)
        
        # IPFS Kalıcılık Adımı: Zinciri kaydet
        new_cid = save_chain_to_ipfs(self.chain) 
        
        return block

    def create_genesis_block(self):
        """Zincirin ilk bloğunu (Genesis Block) oluşturur."""
        self.new_block(data={"message": "Genesis Block", "file_cid": None}, previous_hash="0")
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
st.markdown("Hem blok zinciri hem de yüklenen dosyalar Pinata API'si üzerinden IPFS ağına kaydedilir.")
st.divider()

# -----------------------------------------------------
# YENİ ÜST KONTROL BÖLÜMÜ (Sidebar yerine ana içerikte)
# -----------------------------------------------------
with st.container(border=True):
    
    # İki kolona ayır: 1) Blok Ekleme 2) Kalıcılık Durumu
    col_add, col_status = st.columns([3, 1])

    with col_add:
        st.subheader("📁 Yeni Blok Ekle (Pinata API Kullanılır)")
        
        uploaded_file = st.file_uploader(
            "Blok Zincirine Kayıt Edilecek Dosyayı Yükleyin", 
            type=None, 
            key="file_uploader"
        )
        user_note = st.text_input("Bu kayıtla ilgili notunuz (isteğe bağlı):", max_chars=100)
    
    # Dosya yüklendiğinde ve buton tetiklendiğinde
    if uploaded_file is not None:
        
        # 1. Dosya Hash'ini Hesapla
        file_hash = hash_file(uploaded_file)
        
        # Blok verisini önizle
        preview_data = {
            "Dosya Adı": uploaded_file.name,
            "Dosya Hash (SHA-256)": file_hash,
            "Ek Not": user_note if user_note else "Yok",
            "Dosya CID": "Yüklendikten Sonra Eklenecek..."
        }
        
        col_add.markdown("---")
        col_add.markdown("**Oluşturulacak Blok Verisi:**")
        col_add.json(preview_data)
        
        if col_add.button("Blok Zincirine Ekle ve IPFS'e Kaydet"):
            
            # --- ÖNEMLİ ADIM 1: DOSYAYI IPFS'E YÜKLE ---
            file_cid = upload_file_to_ipfs(uploaded_file, uploaded_file.name)
            
            if file_cid:
                # --- ÖNEMLİ ADIM 2: BLOK VERİSİNİ OLUŞTUR ---
                block_data = {
                    "file_name": uploaded_file.name,
                    "file_hash": file_hash,
                    "note": user_note if user_note else "Yok",
                    "file_cid": file_cid 
                }
                
                # --- ÖNEMLİ ADIM 3: BLOK ZİNCİRİNE EKLE ---
                new_block = blockchain.new_block(data=block_data)
                
                st.toast(f"🎉 Dosya CID'si blok zincirine eklendi!")
                st.balloons()
                st.rerun()

    with col_status:
        st.subheader("IPFS Kalıcılık Durumu")
        st.markdown("---")
        
        if os.path.exists(CID_FILE):
            try:
                with open(CID_FILE, 'r') as f:
                    last_cid = f.read().strip()
                    st.info(f"Son Zincir CID'si: `{last_cid[:10]}...`")
                    st.link_button("IPFS Zincirini Görüntüle", f"{PINATA_GATEWAY}{last_cid}", help="Bu CID, zincirin son durumunu gösterir.")
            except:
                st.error("CID dosyası okunamıyor.")
        else:
            st.warning("Henüz bir CID kaydedilmemiş.")

st.divider()

# -----------------------------------------------------
# ZİNCİRİ GÖRÜNTÜLEME BÖLÜMÜ (Ana İçerik)
# -----------------------------------------------------

st.header(f"⛓️ Blok Zinciri ({len(blockchain.chain)} Blok)")

is_valid, message = blockchain.is_chain_valid()
if is_valid:
    st.success(f"Durum: {message}")
else:
    st.error(f"Durum: 🚨 {message} 🚨")

# Blokları tersten göster (en yeni en üstte)
for block in reversed(blockchain.chain):
    header_text = f"Blok #{block.index}"
    if block.index > 0 and block.data: # Güvenlik için 'block.data' kontrolü eklendi
        header_text += f" - Dosya: {block.data.get('file_name', 'Bilinmiyor')}"
        
    is_latest = block.index == len(blockchain.chain) - 1 and len(blockchain.chain) > 1
    
    with st.expander(f"{header_text} | Hash: {block.hash[:15]}...", expanded=is_latest):
        
        # CID ve diğer bilgileri yan yana göstermek için kolonlar
        col1, col2 = st.columns(2)
        
        # block.data'nın sözlük olup olmadığını kontrol et
        if isinstance(block.data, dict):
            file_cid = block.data.get('file_cid')
        else:
            file_cid = None
            
        with col1:
            st.subheader("Blok Bilgileri")
            st.markdown(f"**Index:** `{block.index}`")
            st.markdown(f"**Zaman Damgası:** `{datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M:%S')}`")
            st.markdown(f"**Nonce:** `{block.nonce}`")
            st.markdown(f"**Önceki Hash:** `{block.previous_hash}`")
            
            # Ek meta verilerini göstermeden önce 'block.data'nın sözlük olduğunu tekrar kontrol et
            if isinstance(block.data, dict) and block.index > 0:
                 st.markdown("---")
                 st.subheader("Ek Meta Verileri")
                 st.json({
                     "Dosya Hash": block.data.get('file_hash'),
                     "Ek Not": block.data.get('note')
                 })
            elif block.data is None:
                 st.error("⚠️ Blok Verisi (Payload) Eksik veya Geçersiz (None).") # Hata durumunda uyarı
        
        with col2:
            st.subheader("Bloğun Hash ve Dosya Adresi")
            st.markdown(f"**Bloğun Kendi Hash'i:**")
            st.code(block.hash)
            
            if file_cid:
                st.markdown("---")
                st.markdown(f"**Dosya IPFS CID (Ağ Adresi):** `{file_cid}`")
                
                # --- İNDİRME BUTONU ---
                download_url = f"{PINATA_GATEWAY}{file_cid}"
                st.link_button(
                    f"💾 Orijinal Dosyayı İndir ({block.data.get('file_name', 'IPFS')})", 
                    download_url,
                    help="Bu düğme, Pinata Ağ Geçidi üzerinden blok zincirine kaydedilen orijinal dosyayı indirir."
                )
            elif block.index == 0:
                st.markdown("Bu, zincirin başlangıç bloğudur (Genesis). Dosya içeriği yoktur.")
            else:
                st.warning("Dosya CID bilgisi bulunamadı.") # Veri eksikse burası tetiklenir
