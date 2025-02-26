# 🛡️ pngcrypt - Secure Steganography with AES-256 & RSA-2048  

### 🔍 Hide and Protect Messages in PNG Images  

`pngcrypt` is a command-line tool that securely hides text messages inside PNG images using **AES-256 encryption + RSA-2048 key protection** and **LSB (Least Significant Bit) steganography**.  

---

## 🚀 Features  
✅ **Strong Encryption**: Uses AES-256 (symmetric) + RSA-2048 (asymmetric) for **high security**.  
✅ **Lossless Steganography**: Embeds messages without altering image quality.  
✅ **PNG Support**: Works exclusively with **valid PNG** images.  
✅ **Integrity Check**: Ensures the image is a valid stego PNG before decryption.  
✅ **Command-line Tool**: Simple-to-use CLI with encryption and decryption modes.  

---

## 🛠️ Technologies Used  
- **Python 3**  
- **OpenSSL** (for RSA key generation)  
- **Libraries**: `argparse`, `cv2 (OpenCV)`, `numpy`, `pycryptodome`, `base64`, `struct`  

---

## 📌 Installation  
### 1️⃣ Clone the Repository  
```bash
git clone https://github.com/abdulbaasith005/pngcrypt.git
cd pngcrypt
