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
```
### Prerequisites
Ensure you have Python 3.x installed along with the required dependencies.

```bash
pip install -r requirements.txt
```

## 🔑 Generating RSA Key Pairs (via OpenSSL)

Before using `pngcrypt`, generate a pair of RSA keys:

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
```

## 🚀 Usage

### 🔹 Encrypt a Message into a PNG

```bash
python pngcrypt.py -e -i input.png -t message.txt -pub public.pem -o output.png
```
### 🔹 Decrypt a Message from a PNG

```bash
python pngcrypt.py -d -i steg.png -pvt private.pem -o decrypted.txt
```

## 🌟 Why pngcrypt?

✔ **Strong Encryption:** Uses AES-256 for message encryption and RSA-2048 for key protection.  
✔ **Secure Transmission:** Message cannot be decrypted without the correct private key.  
✔ **Lossless Steganography:** Embeds data without significantly altering image quality.  
✔ **CLI-Based:** Easily integrate into scripts or automation workflows.  

## 🔮 Future Enhancements

✅ Support for JPEG and BMP formats  
✅ GUI version for better user experience  
✅ Improved compression for larger messages  

## 📜 License

This project is open-source and available under the MIT License.  

🚀 **Secure your messages with pngcrypt today!** 🔏  

