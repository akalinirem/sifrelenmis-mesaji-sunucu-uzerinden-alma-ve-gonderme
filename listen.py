import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Şifreleme anahtarı
key = get_random_bytes(16)

# Sunucunun IP adresi ve bağlantı noktası
IP = "0.0.0.0"
PORT = 5555

def encrypt_message(message):
    # CBC modunda ve rastgele  bir başlatma vektörü ile AES algoritması kullanarak şifreleme
    cipher = AES.new(key, AES.MODE_CBC)
    # Şifrelenmiş mesajı, başlatma vektörü ile birleştirerek döndürme
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    return iv + ciphertext

def decrypt_message(encrypted_message):
    # Şifrelenmiş mesajın ilk bloğu IV olarak ayarlanır
    iv = encrypted_message[:AES.block_size]
    ciphertext = encrypted_message[AES.block_size:]
    # CBC modunda AES şifreleyici oluşturur
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    # Dekodlama işlemiyle karakter dizisine dönüştürülerek döndürülür
    return decrypted_message.decode()

# Sunucu soketi oluşturma
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((IP, PORT))
    s.listen()

    print("Sunucu dinlemede...")

    conn, addr = s.accept()
    with conn:
        print(f"{addr} bağlandı.")

        # Şifreli veriyi al
        encrypted_data = conn.recv(1024) 
        # decrypted_data = decrypt_message(encrypted_data)
        
        print("Şifreli veri alındı:", encrypted_data)
        # print("İşlenen veri:", decrypted_data)

print("Sunucu kapatıldı.")
