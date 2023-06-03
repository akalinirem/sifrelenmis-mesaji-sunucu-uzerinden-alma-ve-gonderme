import socket

# Sunucunun IP adresi ve bağlantı noktası
IP = "192.654.55.518"
PORT = 5555

# Örnek olarak varsayılan bir şifrelenmiş mesaj
encrypted_message = b"\x12\x34\x56\x78\x90\xab\xcd\xef"  

# Sunucuya bağlanma
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((IP, PORT))
    
    # Şifreli mesajı gönderme
    s.sendall(encrypted_message)

print("Şifreli mesaj gönderildi.")