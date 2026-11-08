import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

class KriptografiApp:
    def __init__(self):
        pass

    # ==========================================
    # 1. ALGORITMA SIMETRIS: ChaCha20-Poly1305
    # ==========================================
    def simetris_generate_key(self):
        # ChaCha20 membutuhkan kunci sepanjang 32 byte (256-bit)
        return ChaCha20Poly1305.generate_key()

    def simetris_encrypt(self, key: bytes, plaintext: str) -> dict:
        chacha = ChaCha20Poly1305(key)
        # 96-bit (12 byte) nonce acak yang unik untuk setiap enkripsi
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Gabungkan nonce dan ciphertext lalu encode ke Base64 agar mudah dibaca/disimpan
        encrypted_data = base64.b64encode(nonce + ciphertext).decode('utf-8')
        return {"ciphertext": encrypted_data}

    def simetris_decrypt(self, key: bytes, encrypted_b64: str) -> str:
        chacha = ChaCha20Poly1305(key)
        decoded_data = base64.b64decode(encrypted_b64.encode('utf-8'))
        
        # Pisahkan nonce (12 byte pertama) dan ciphertext
        nonce = decoded_data[:12]
        ciphertext = decoded_data[12:]
        
        plaintext_bytes = chacha.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')

    # ==========================================
    # 2. ALGORITMA ASIMETRIS: Elliptic Curve (ECC)
    # Catatan: ECC digunakan untuk enkripsi/dekripsi atau tanda tangan digital. 
    # Untuk enkripsi asimetris selain RSA, ECIES umum digunakan. 
    # Di sini kita simulasikan pertukaran/keamanan asimetris.
    # ==========================================
    def asimetris_generate_keys(self):
        # Menggunakan kurva SECP256R1
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        return private_key, public_key

    # Implementasi Enkripsi Asimetris menggunakan Hybrid Encryption (ECC + ChaCha20)
    # Mengingat ECC murni mendefinisikan key exchange / signature, standar praktis 
    # enkripsi pesan teks panjang dengan asimetris non-RSA menggunakan ECIES / Hybrid.
    def asimetris_encrypt(self, public_key, plaintext: str) -> dict:
        # Generate ephemeral private key untuk ECDH
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), public_key)
        
        # Gunakan shared key sebagai kunci ChaCha20
        derived_key = hashes.Hash(hashes.SHA256())
        derived_key.update(shared_key)
        sym_key = derived_key.finalize()[:32]
        
        chacha = ChaCha20Poly1305(sym_key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Kirim ephemeral public key agar penerima bisa menghitung shared key yang sama
        ephemeral_public_key = ephemeral_private_key.public_key()
        from cryptography.hazmat.primitives import serialization
        pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        payload = base64.b64encode(pub_bytes + nonce + ciphertext).decode('utf-8')
        return {"ciphertext": payload}

    def asimetris_decrypt(self, private_key, encrypted_b64: str) -> str:
        decoded_data = base64.b64decode(encrypted_b64.encode('utf-8'))
        
        # Ekstrak komponen
        # Karena ukuran DER public key ECC sekira 91 byte:
        pub_bytes_len = 91 
        pub_bytes = decoded_data[:pub_bytes_len]
        nonce = decoded_data[pub_bytes_len:pub_bytes_len+12]
        ciphertext = decoded_data[pub_bytes_len+12:]
        
        from cryptography.hazmat.primitives import serialization
        ephemeral_public_key = serialization.load_der_public_key(pub_bytes)
        
        shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
        derived_key = hashes.Hash(hashes.SHA256())
        derived_key.update(shared_key)
        sym_key = derived_key.finalize()[:32]
        
        chacha = ChaCha20Poly1305(sym_key)
        plaintext_bytes = chacha.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')


# ==========================================
# MENU UTAMA APLIKASI CLI
# ==========================================
def main():
    app = KriptografiApp()
    
    # Variabel Penyimpanan Sementara di Memori
    sim_key = app.simetris_generate_key()
    asym_priv, asym_pub = app.asimetris_generate_keys()

    while True:
        print("\n==============================================")
        print("   PROGRAM APLIKASI KRIPTOGRAFI (SELAIN AES/RSA)")
        print("   Simetris: ChaCha20 | Asimetris: ECC (ECIES)")
        print("==============================================")
        print("1. Enkripsi Pesan (Simetris)")
        print("2. Dekripsi Pesan (Simetris)")
        print("3. Enkripsi Pesan (Asimetris)")
        print("4. Dekripsi Pesan (Asimetris)")
        print("5. Keluar")
        
        pilihan = input("Pilih menu (1-5): ")

        if pilihan == "1":
            teks = input("\nMasukkan teks yang akan dienkripsi: ")
            hasil = app.simetris_encrypt(sim_key, teks)
            print(f"\n[HASIL ENKRIPSI SIMETRIS]:\n{hasil['ciphertext']}")
            print(f"(Simpan kunci simetris Anda dalam bytes jika perlu: {base64.b64encode(sim_key).decode('utf-8')})")

        elif pilihan == "2":
            teks_cipher = input("\nMasukkan teks ciphertext (Base64): ")
            try:
                hasil = app.simetris_decrypt(sim_key, teks_cipher)
                print(f"\n[HASIL DEKRIPSI SIMETRIS]:\n{hasil}")
            except Exception as e:
                print(f"\nGagal mendekripsi! Pastikan ciphertext benar. Error: {e}")

        elif pilihan == "3":
            teks = input("\nMasukkan teks yang akan dienkripsi: ")
            hasil = app.asimetris_encrypt(asym_pub, teks)
            print(f"\n[HASIL ENKRIPSI ASIMETRIS]:\n{hasil['ciphertext']}")

        elif pilihan == "4":
            teks_cipher = input("\nMasukkan teks ciphertext (Base64): ")
            try:
                hasil = app.asimetris_decrypt(asym_priv, teks_cipher)
                print(f"\n[HASIL DEKRIPSI ASIMETRIS]:\n{hasil}")
            except Exception as e:
                print(f"\nGagal mendekripsi! Pastikan ciphertext benar. Error: {e}")

        elif pilihan == "5":
            print("\nKeluar dari program. Terima kasih!")
            break
        else:
            print("\nPilihan tidak valid. Silakan pilih angka 1-5.")

if __name__ == "__main__":
    main()