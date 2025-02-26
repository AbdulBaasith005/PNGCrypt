import argparse
import cv2
import numpy as np
import struct
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

def is_png(image_path):
    if not image_path.lower().endswith('.png'):
        return False
    try:
        with open(image_path, 'rb') as f:
            signature = f.read(8)
        return signature == b'\x89PNG\r\n\x1a\n'
    except Exception:
        return False

def generate_aes_key():
    return get_random_bytes(32)

def encrypt_aes(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_aes(encrypted_data, key):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def encrypt_rsa(data, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(data)

def decrypt_rsa(encrypted_data, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_data)

def encode_message_to_image(image_path, message, public_key_path, output_image):
    if not is_png(image_path):
        raise ValueError("Input file must be a PNG image.")
    
    aes_key = generate_aes_key()
    encrypted_message = encrypt_aes(message.encode(), aes_key)
    encrypted_aes_key = encrypt_rsa(aes_key, public_key_path)
    
    payload = struct.pack('H', len(encrypted_aes_key)) + encrypted_aes_key + encrypted_message
    payload_b64 = base64.b64encode(payload).decode()
    
    payload_length = len(payload_b64)
    header = format(payload_length, '032b')
    payload_binary = ''.join(format(ord(c), '08b') for c in payload_b64)
    binary_payload = header + payload_binary

    image = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if image is None:
        raise ValueError("Failed to load image. Ensure the file exists and is a valid PNG.")
    
    flat_image = image.flatten()

    if len(binary_payload) > flat_image.size:
        raise ValueError("Message is too large to encode in the image.")

    binary_payload_array = np.array(list(map(int, binary_payload)), dtype=np.uint8)
    flat_image[:len(binary_payload)] = (flat_image[:len(binary_payload)] & 254) | binary_payload_array

    image = flat_image.reshape(image.shape)
    cv2.imwrite(output_image, image)
    print(f"Stego image saved as {output_image}")

def decode_message_from_image(image_path, private_key_path, output_text):
    if not is_png(image_path):
        raise ValueError("Input file must be a PNG image.")
    
    image = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
    if image is None:
        raise ValueError("Failed to load image. Ensure the file exists and is a valid PNG.")
    
    flat_image = image.flatten()

    binary_payload = (flat_image & 1).astype(str)
    binary_payload_str = ''.join(binary_payload)

    header = binary_payload_str[:32]
    payload_length = int(header, 2)

    payload_bits = binary_payload_str[32:32 + payload_length * 8]

    byte_data = np.array([int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8)], dtype=np.uint8).tobytes()

    try:
        payload = base64.b64decode(byte_data, validate=True)
        key_length = struct.unpack('H', payload[:2])[0]
        encrypted_aes_key = payload[2:2+key_length]
        encrypted_message = payload[2+key_length:]
        
        aes_key = decrypt_rsa(encrypted_aes_key, private_key_path)
        message = decrypt_aes(encrypted_message, aes_key).decode()
        
        with open(output_text, "w") as f:
            f.write(message)
        print(f"Decrypted message saved as {output_text}")
    except Exception as e:
        raise ValueError("Failed to decrypt. Ensure this is a valid stego image.") from e

def main():
    parser = argparse.ArgumentParser(description="pngcrypt_ab: PNG Steganography with AES-256 + RSA-2048")
    parser.add_argument("-e", "--encrypt", action="store_true", help="Encrypt message into PNG image")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt message from PNG stego image")
    parser.add_argument("-i", "--input", required=True, help="Input image file")
    parser.add_argument("-t", "--text", help="Text file containing message (for encryption)")
    parser.add_argument("-pub", "--public", help="Public key file (for encryption)")
    parser.add_argument("-pvt", "--private", help="Private key file (for decryption)")
    parser.add_argument("-o", "--output", required=True, help="Output file")
    
    args = parser.parse_args()
    
    if args.encrypt:
        if not args.text or not args.public:
            raise ValueError("Encryption mode requires -t (text file) and -pub (public key)")
        with open(args.text, "r") as f:
            message = f.read()
        encode_message_to_image(args.input, message, args.public, args.output)
    
    elif args.decrypt:
        if not args.private:
            raise ValueError("Decryption mode requires -pvt (private key)")
        decode_message_from_image(args.input, args.private, args.output)
    else:
        raise ValueError("Specify either -e (encrypt) or -d (decrypt) mode.")

if __name__ == "__main__":
    main()
