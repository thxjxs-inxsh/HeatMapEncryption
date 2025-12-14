from flask import Flask, render_template, request, jsonify
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html") 

@app.route("/encrypt_message", methods=["POST"])
def encrypt_message():
    data = request.get_json()
    message = data.get("message")
    key_hex = data.get("key")

    if not message or not key_hex:
        return jsonify({"encrypted_message": ""}), 400

    try:
        key_bytes = bytes.fromhex(key_hex)[:32]  # AES-256 key
        cipher = AES.new(key_bytes, AES.MODE_ECB)  # simple mode for demo
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        encrypted_hex = binascii.hexlify(ciphertext).decode()
        return jsonify({"encrypted_message": encrypted_hex})
    except Exception as e:
        print("Error encrypting message:", e)
        return jsonify({"encrypted_message": "Error"}), 500

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.get_json()
    images = data.get("images")

    if not images:
        return jsonify({"status": "No images received"}), 400

    try:
        combined_bytes = b"".join(base64.b64decode(img.split(",",1)[1]) for img in images)
        key = hashlib.sha256(combined_bytes).hexdigest()
        print("Generated key:", key)
        return jsonify({"status": f"Received {len(images)} images", "key": key})
    except Exception as e:
        print("Error generating key:", e)
        return jsonify({"status": "Error generating key"}), 500

if __name__ == "__main__":
    app.run(debug=True)
