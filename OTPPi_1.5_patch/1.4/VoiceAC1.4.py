import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, scrolledtext
import tkinter.simpledialog
import socket
import threading
from pathlib import Path
import fcntl
import json
import base64
import uuid
import secrets
from typing import Optional

import speech_recognition as sr
import pyttsx3

# --- v1.5 additions: AES + OTP-Lite support ---
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

MAX_OTPLITE_LEN = 1024  # bytes


def load_otp_pages(file_name="otp_cipher.txt"):
    otp_pages = []
    file_path = Path(file_name)
    if not file_path.exists():
        return otp_pages
    with file_path.open("r") as file:
        for line in file:
            if len(line) < 8:
                continue
            identifier = line[:8]
            content = line[8:].strip()
            otp_pages.append((identifier, content))
    return otp_pages

def load_used_pages(file_name="used_pages.txt"):
    file_path = Path(file_name)
    if not file_path.exists():
        return set()
    with file_path.open("r") as file:
        return {line.strip() for line in file}

def save_used_page(identifier, file_name="used_pages.txt"):
    with open(file_name, "a") as file:
        file.write(f"{identifier}\n")

def get_next_otp_page_linux(otp_pages, used_identifiers, lock_file="used_pages.lock"):
    """Find the next unused OTP page based on identifiers with a locking mechanism on Linux."""
    with open(lock_file, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for identifier, content in otp_pages:
            if identifier not in used_identifiers:
                save_used_page(identifier)
                used_identifiers.add(identifier)
                fcntl.flock(lock, fcntl.LOCK_UN)
                return identifier, content
        fcntl.flock(lock, fcntl.LOCK_UN)
    return None, None

def encrypt_message(message, otp_content):
    encrypted_message = []
    for i, char in enumerate(message):
        if i >= len(otp_content):
            break
        encrypted_char = chr(ord(char) ^ ord(otp_content[i]))
        encrypted_message.append(encrypted_char)
    return ''.join(encrypted_message)

def decrypt_message(encrypted_message, otp_content):
    decrypted_message = []
    for i, char in enumerate(encrypted_message):
        if i >= len(otp_content):
            break
        decrypted_char = chr(ord(char) ^ ord(otp_content[i]))
        decrypted_message.append(decrypted_char)
    return ''.join(decrypted_message)


def _json_dumps(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))


def _safe_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

#OTPClient class
class OTPClient:
    def __init__(self, master):
        self.master = master
        self.master.title("OTP Messaging Client (v1.5)")

        self.master.geometry("700x600")
        self.master.minsize(600, 500)

        style = ttk.Style()
        style.theme_use('clam') 

        menu_bar = tk.Menu(self.master)
        self.master.config(menu=menu_bar)

        file_menu = tk.Menu(menu_bar, tearoff=False)
        file_menu.add_command(label="About", command=self.show_about_info)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.master.quit)
        menu_bar.add_cascade(label="File", menu=file_menu)

        self.user_id_file = Path("user_id.txt")
        self.user_id = self.load_or_prompt_user_id()

        self.otp_pages = load_otp_pages()
        self.used_identifiers = load_used_pages()

        # --- v1.5 crypto state ---
        # RSA keys: used for OTP-Lite pad delivery (server encrypts pad material to each client).
        self.rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_pub_pem = self.rsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.rsa_pub_b64 = _b64e(rsa_pub_pem)

        # X25519 keys: used for peer-to-peer ECDH to derive an AES session key.
        self.x25519_private = X25519PrivateKey.generate()
        self.x25519_public_b64 = _b64e(
            self.x25519_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

        self.aes_keys = {}              # peer_user_id -> 32-byte AES key
        self._aes_kx_events = {}        # peer_user_id -> threading.Event
        self._aes_kx_lock = threading.Lock()

        self.otplite_pads = {}          # msg_id -> pad bytes
        self._otplite_events = {}       # msg_id -> threading.Event (sender-side)
        self._otplite_pending_ct = {}   # msg_id -> (sender_id, ciphertext_bytes)

        self.SERVER_HOST = None
        self.SERVER_PORT = None
        self.client_socket = None

        self.chat_history_file = Path(f"chat_history_{self.user_id}.txt") if self.user_id else None

        self.main_frame = ttk.Frame(self.master, padding="10 10 10 10")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)

        self.server_frame = ttk.Frame(self.main_frame, padding=(0, 10, 0, 10))
        self.server_frame.grid(row=0, column=0, sticky="ew")

        self.user_id_frame = ttk.Frame(self.main_frame, padding=(0, 10, 0, 10))
        self.user_id_frame.grid(row=1, column=0, sticky="ew")

        self.message_frame = ttk.Frame(self.main_frame)
        self.message_frame.grid(row=2, column=0, sticky="nsew")

        self.main_frame.columnconfigure(0, weight=1)

        ttk.Label(self.server_frame, text="Ngrok Host:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.ngrok_host_entry = ttk.Entry(self.server_frame, width=20)
        self.ngrok_host_entry.insert(0, "0.tcp.ngrok.io")
        self.ngrok_host_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.server_frame, text="Ngrok Port:").grid(row=0, column=2, padx=5, pady=5, sticky="e")
        self.ngrok_port_entry = ttk.Entry(self.server_frame, width=10)
        self.ngrok_port_entry.insert(0, "12345")
        self.ngrok_port_entry.grid(row=0, column=3, padx=5, pady=5)

        self.set_server_button = ttk.Button(self.server_frame, text="Set Server Address", command=self.set_server_address)
        self.set_server_button.grid(row=0, column=4, padx=10, pady=5)

        ttk.Label(self.user_id_frame, text="Your userID:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.user_id_entry = ttk.Entry(self.user_id_frame, width=30)
        self.user_id_entry.grid(row=0, column=1, padx=5, pady=5)

        if self.user_id:
            self.user_id_entry.insert(0, self.user_id)

        self.connect_button = ttk.Button(self.user_id_frame, text="Connect", command=self.connect_to_server)
        self.connect_button.grid(row=0, column=2, padx=10, pady=5)

        self.user_id_display = ttk.Label(self.message_frame, text="", style="Bold.TLabel")
        self.user_id_display.grid(row=0, column=0, columnspan=3, padx=5, pady=5, sticky="ew")

        self.chat_area = scrolledtext.ScrolledText(self.message_frame, width=60, height=15, state=tk.DISABLED)
        self.chat_area.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")
        self.message_frame.rowconfigure(1, weight=1)

        # Encryption mode selection
        ttk.Label(self.message_frame, text="Encryption:").grid(row=2, column=0, padx=5, sticky="e")
        self.mode_var = tk.StringVar(value="OTP")
        self.mode_combo = ttk.Combobox(self.message_frame, textvariable=self.mode_var, values=["OTP", "OTP-Lite", "AES"], state="readonly", width=12)
        self.mode_combo.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(self.message_frame, text="Recipient userID:").grid(row=3, column=0, padx=5, sticky="e")
        self.recipient_input = ttk.Entry(self.message_frame, width=40)
        self.recipient_input.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(self.message_frame, text="Message:").grid(row=4, column=0, padx=5, sticky="e")
        self.text_input = ttk.Entry(self.message_frame, width=40)
        self.text_input.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        self.send_button = ttk.Button(self.message_frame, text="Send Text Message", command=self.send_message)
        self.send_button.grid(row=5, column=0, padx=5, pady=5, sticky="e")

        self.record_button = ttk.Button(self.message_frame, text="Record Voice Message", command=self.send_voice_message)
        self.record_button.grid(row=5, column=1, padx=5, pady=5, sticky="w")

        for child in self.message_frame.winfo_children():
            child.grid_remove()

    def show_about_info(self):
        messagebox.showinfo("About", "OTP Messaging Client\nVersion 1.5\nModes: OTP / OTP-Lite / AES\nUsing Tkinter & Python.")

    def load_or_prompt_user_id(self):
        if self.user_id_file.exists():
            existing = self.user_id_file.read_text().strip()
            if existing:
                return existing
        return None

    def save_user_id_to_file(self, user_id):
        with self.user_id_file.open("w") as f:
            f.write(user_id)

    def set_server_address(self):
        host = self.ngrok_host_entry.get().strip()
        port = self.ngrok_port_entry.get().strip()
        if not host or not port:
            messagebox.showwarning("Warning", "Please enter both Ngrok host and port.")
            return
        if not port.isdigit():
            messagebox.showwarning("Warning", "Port must be a number.")
            return

        self.SERVER_HOST = host
        self.SERVER_PORT = int(port)
        messagebox.showinfo("Info", f"Server address set to {self.SERVER_HOST}:{self.SERVER_PORT}")

        self.ngrok_host_entry.config(state=tk.DISABLED)
        self.ngrok_port_entry.config(state=tk.DISABLED)
        self.set_server_button.config(state=tk.DISABLED)

    def connect_to_server(self):
        if self.SERVER_HOST is None or self.SERVER_PORT is None:
            messagebox.showwarning("Warning", "Please set the server address first.")
            return

        self.user_id = self.user_id_entry.get().strip()
        if not self.user_id:
            messagebox.showwarning("Warning", "Please enter a userID.")
            return

        self.save_user_id_to_file(self.user_id)

        self.chat_history_file = Path(f"chat_history_{self.user_id}.txt")

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.SERVER_HOST, self.SERVER_PORT))
            self.client_socket.sendall(self.user_id.encode("utf-8"))
            response = self.client_socket.recv(1024).decode("utf-8")

            if response in ["UserID already taken. Connection closed.", "Invalid userID. Connection closed."]:
                messagebox.showerror("Error", response)
                self.client_socket.close()
                return

            messagebox.showinfo("Info", "Connected to the server.")

            for child in self.user_id_frame.winfo_children():
                child.grid_remove()
            for child in self.message_frame.winfo_children():
                child.grid()

            self.user_id_display.config(text=f"Your userID: {self.user_id}")

            self.load_chat_history()

            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()

            # Register client public keys with the server (used for OTP-Lite pad delivery).
            self.register_keys_with_server()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect to the server: {e}")

    def load_chat_history(self):
        if self.chat_history_file and self.chat_history_file.exists():
            with self.chat_history_file.open("r", encoding="utf-8") as f:
                for line in f:
                    self.update_chat_area(line.strip(), save_to_file=False)

    def save_chat_line(self, message):
        if self.chat_history_file:
            with self.chat_history_file.open("a", encoding="utf-8") as f:
                f.write(message + "\n")

    def get_next_available_otp(self):
        return get_next_otp_page_linux(self.otp_pages, self.used_identifiers)

    # --- Protocol helpers ---
    def _send_to_server(self, recipient_id: str, payload_str: str):
        if not self.client_socket:
            raise RuntimeError("Not connected")
        wire = f"{recipient_id}|{payload_str}".encode("utf-8")
        self.client_socket.sendall(wire)

    def send_json(self, recipient_id: str, payload: dict):
        self._send_to_server(recipient_id, _json_dumps(payload))

    def register_keys_with_server(self):
        try:
            self.send_json("__server__", {"t": "REGISTER_KEYS", "rsa_pub": self.rsa_pub_b64})
        except Exception:
            # Not fatal; OTP mode still works.
            pass

    # --- AES mode (client-to-client, routed by server) ---
    def _derive_aes_key(self, shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"OTPPi-AES-v1.5",
        ).derive(shared_secret)

    def _ensure_aes_session(self, peer_user_id: str, timeout_s: float = 10.0) -> bool:
        if peer_user_id in self.aes_keys:
            return True

        with self._aes_kx_lock:
            ev = self._aes_kx_events.get(peer_user_id)
            if not ev:
                ev = threading.Event()
                self._aes_kx_events[peer_user_id] = ev

                # Kick off handshake (KX1)
                self.send_json(peer_user_id, {"t": "AES_KX1", "pub": self.x25519_public_b64})

        # Wait for key establishment
        return ev.wait(timeout=timeout_s)

    def _aes_encrypt(self, peer_user_id: str, plaintext: str) -> dict:
        key = self.aes_keys[peer_user_id]
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        msg_id = uuid.uuid4().hex
        aad = f"{msg_id}|{self.user_id}|{peer_user_id}".encode("utf-8")
        ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return {"t": "AES_MSG", "msg_id": msg_id, "nonce": _b64e(nonce), "ct": _b64e(ct)}

    def _aes_decrypt(self, sender_id: str, payload: dict) -> str:
        key = self.aes_keys.get(sender_id)
        if not key:
            raise ValueError("No AES session key for sender")
        aesgcm = AESGCM(key)
        msg_id = payload.get("msg_id")
        nonce = _b64d(payload["nonce"])
        ct = _b64d(payload["ct"])
        aad = f"{msg_id}|{sender_id}|{self.user_id}".encode("utf-8")
        pt = aesgcm.decrypt(nonce, ct, aad)
        return pt.decode("utf-8", errors="replace")

    # --- OTP-Lite mode (server-generated one-time pad per message) ---
    def _request_otplite_pad(self, peer_user_id: str, msg_id: str, length: int, timeout_s: float = 10.0) -> Optional[bytes]:
        ev = threading.Event()
        self._otplite_events[msg_id] = ev
        self.send_json("__server__", {"t": "OTPLITE_REQUEST", "to": peer_user_id, "msg_id": msg_id, "length": length})
        if not ev.wait(timeout=timeout_s):
            self._otplite_events.pop(msg_id, None)
            return None
        return self.otplite_pads.get(msg_id)

    def send_message(self):
        recipient_id = self.recipient_input.get().strip()
        message = self.text_input.get()

        if not recipient_id:
            messagebox.showwarning("Warning", "Please enter a valid recipient userID.")
            return
        if not message:
            messagebox.showwarning("Warning", "Please enter a message.")
            return
        if recipient_id == self.user_id:
            messagebox.showwarning("Warning", "You cannot send a message to yourself.")
            return

        mode = self.mode_var.get().strip()

        # --- AES ---
        if mode == "AES":
            try:
                if not self._ensure_aes_session(recipient_id):
                    messagebox.showerror("Error", "AES handshake timed out (other client may not be connected / not updated).")
                    return
                payload = self._aes_encrypt(recipient_id, message)
                self.send_json(recipient_id, payload)
                self.text_input.delete(0, tk.END)
                self.update_chat_area(f"Me to {recipient_id} (AES): {message}")
                return
            except Exception as e:
                messagebox.showerror("Error", f"AES send failed: {e}")
                return

        # --- OTP-Lite ---
        if mode == "OTP-Lite":
            try:
                msg_id = uuid.uuid4().hex
                pt = message.encode("utf-8")
                if len(pt) > MAX_OTPLITE_LEN:
                    messagebox.showerror("Error", f"OTP-Lite messages are limited to {MAX_OTPLITE_LEN} bytes in this demo. Use AES for longer messages.")
                    return
                pad = self._request_otplite_pad(recipient_id, msg_id, len(pt))
                if not pad:
                    messagebox.showerror("Error", "OTP-Lite pad request timed out (ensure both clients are connected + registered keys).")
                    return
                ct = _xor_bytes(pt, pad)
                self.send_json(recipient_id, {"t": "OTPLITE_MSG", "msg_id": msg_id, "ct": _b64e(ct)})

                # One-time use: wipe local pad once used.
                self.otplite_pads.pop(msg_id, None)
                self._otplite_events.pop(msg_id, None)

                self.text_input.delete(0, tk.END)
                self.update_chat_area(f"Me to {recipient_id} (OTP-Lite): {message}")
                return
            except Exception as e:
                messagebox.showerror("Error", f"OTP-Lite send failed: {e}")
                return

        # --- OTP (existing behaviour) ---
        otp_identifier, otp_content = self.get_next_available_otp()
        if otp_identifier and otp_content:
            encrypted_message = encrypt_message(message, otp_content)
            full_message = f"{recipient_id}|{otp_identifier}:{encrypted_message}"
            if self.client_socket:
                try:
                    self.client_socket.sendall(full_message.encode("utf-8"))
                    self.text_input.delete(0, tk.END)
                    display_line = f"Me to {recipient_id}: {message}"
                    self.update_chat_area(display_line)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to send message: {e}")
        else:
            messagebox.showerror("Error", "No available OTP pages to use.")

    def receive_messages(self):
        while True:
            try:
                if not self.client_socket:
                    break

                data = self.client_socket.recv(4096)
                if not data:
                    break

                wire = data.decode("utf-8", errors="replace")

                # Most messages are in the form: sender_id|payload
                if "|" not in wire:
                    self.update_chat_area(wire)
                    continue

                sender_id, payload_str = wire.split("|", 1)

                # Try JSON protocol first (AES / OTP-Lite / server notices)
                payload = _safe_json_loads(payload_str)
                if isinstance(payload, dict) and payload.get("t"):
                    t = payload.get("t")

                    # Server notices
                    if t == "ERROR":
                        self.update_chat_area(f"Server error: {payload.get('msg', 'Unknown error')}")
                        continue
                    if t == "KEYS_OK":
                        # Silent success
                        continue

                    # AES key exchange
                    if t == "AES_KX1":
                        try:
                            peer_pub = X25519PublicKey.from_public_bytes(_b64d(payload["pub"]))
                            shared = self.x25519_private.exchange(peer_pub)
                            self.aes_keys[sender_id] = self._derive_aes_key(shared)

                            # Reply with our public key
                            self.send_json(sender_id, {"t": "AES_KX2", "pub": self.x25519_public_b64})

                            with self._aes_kx_lock:
                                ev = self._aes_kx_events.get(sender_id)
                                if ev:
                                    ev.set()

                            self.update_chat_area(f"AES session established with {sender_id}.")
                        except Exception as e:
                            self.update_chat_area(f"AES handshake failed from {sender_id}: {e}")
                        continue

                    if t == "AES_KX2":
                        try:
                            peer_pub = X25519PublicKey.from_public_bytes(_b64d(payload["pub"]))
                            shared = self.x25519_private.exchange(peer_pub)
                            self.aes_keys[sender_id] = self._derive_aes_key(shared)

                            with self._aes_kx_lock:
                                ev = self._aes_kx_events.get(sender_id)
                                if ev:
                                    ev.set()

                            self.update_chat_area(f"AES session established with {sender_id}.")
                        except Exception as e:
                            self.update_chat_area(f"AES handshake failed from {sender_id}: {e}")
                        continue

                    if t == "AES_MSG":
                        try:
                            pt = self._aes_decrypt(sender_id, payload)
                            display_line = f"Received from {sender_id} (AES): {pt}"
                            self.update_chat_area(display_line)
                            threading.Thread(target=self.speak_text, args=(pt,), daemon=True).start()
                        except Exception as e:
                            self.update_chat_area(f"Failed to decrypt AES message from {sender_id}: {e}")
                        continue

                    # OTP-Lite pad delivery (from server)
                    if t == "OTPLITE_PAD":
                        try:
                            msg_id = payload["msg_id"]
                            ek = _b64d(payload["ek"])
                            nonce = _b64d(payload["nonce"])
                            ct = _b64d(payload["ct"])

                            aes_key = self.rsa_private_key.decrypt(
                                ek,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None,
                                ),
                            )
                            pad_bytes = AESGCM(aes_key).decrypt(nonce, ct, None)
                            self.otplite_pads[msg_id] = pad_bytes

                            # Wake any sender waiting for this pad
                            ev = self._otplite_events.get(msg_id)
                            if ev:
                                ev.set()

                            # If ciphertext already arrived, decrypt now
                            pending = self._otplite_pending_ct.pop(msg_id, None)
                            if pending:
                                pending_sender, pending_ct = pending
                                pt_bytes = _xor_bytes(pending_ct, pad_bytes)
                                pt = pt_bytes.decode("utf-8", errors="replace")
                                self.update_chat_area(f"Received from {pending_sender} (OTP-Lite): {pt}")
                                threading.Thread(target=self.speak_text, args=(pt,), daemon=True).start()
                                self.otplite_pads.pop(msg_id, None)
                        except Exception as e:
                            self.update_chat_area(f"Failed to process OTP-Lite pad: {e}")
                        continue

                    # OTP-Lite ciphertext (from peer)
                    if t == "OTPLITE_MSG":
                        try:
                            msg_id = payload["msg_id"]
                            ct_bytes = _b64d(payload["ct"])
                            pad_bytes = self.otplite_pads.get(msg_id)
                            if not pad_bytes:
                                # Pad may arrive slightly after ciphertext
                                self._otplite_pending_ct[msg_id] = (sender_id, ct_bytes)
                                self.update_chat_area(f"Received OTP-Lite message from {sender_id} (waiting for pad...)" )
                                continue

                            pt_bytes = _xor_bytes(ct_bytes, pad_bytes)
                            pt = pt_bytes.decode("utf-8", errors="replace")
                            self.update_chat_area(f"Received from {sender_id} (OTP-Lite): {pt}")
                            threading.Thread(target=self.speak_text, args=(pt,), daemon=True).start()
                            self.otplite_pads.pop(msg_id, None)
                        except Exception as e:
                            self.update_chat_area(f"Failed to decrypt OTP-Lite message from {sender_id}: {e}")
                        continue

                    # Unknown JSON message type
                    self.update_chat_area(f"Received {t} from {sender_id}: {payload_str}")
                    continue

                # Fallback: legacy OTP wire format (otp_id:ciphertext)
                try:
                    otp_identifier, actual_encrypted_message = payload_str.split(":", 1)
                except ValueError:
                    self.update_chat_area(f"Received from {sender_id}: {payload_str}")
                    continue

                otp_content = None
                for identifier, content in self.otp_pages:
                    if identifier == otp_identifier:
                        otp_content = content
                        break

                if otp_content:
                    decrypted_message = decrypt_message(actual_encrypted_message, otp_content)
                    display_line = f"Received from {sender_id} (OTP): {decrypted_message}"
                    self.update_chat_area(display_line)
                    threading.Thread(target=self.speak_text, args=(decrypted_message,), daemon=True).start()
                    save_used_page(otp_identifier)
                    self.used_identifiers.add(otp_identifier)
                else:
                    self.update_chat_area(f"Received from {sender_id} (Unknown OTP): {actual_encrypted_message}")

            except Exception as e:
                print(f"Error receiving message: {e}")
                break
                
        #Close the client socket if it is still open
        if self.client_socket:
            self.client_socket.close()
        #Notify the user that the connection has been disconnected
        messagebox.showwarning("Warning", "Disconnected from the server.")
        self.master.quit()

    def update_chat_area(self, message, save_to_file=True):
        self.chat_area.config(state=tk.NORMAL)
        self.chat_area.insert(tk.END, message + "\n")
        self.chat_area.config(state=tk.DISABLED)
        self.chat_area.yview(tk.END)

        if save_to_file:
            self.save_chat_line(message)

    def record_voice_message(self):
        r = sr.Recognizer()
        mic = sr.Microphone()
        try:
            with mic as source:
                self.update_chat_area("Adjusting for ambient noise... Please wait.")
                r.adjust_for_ambient_noise(source)
                self.update_chat_area("Recording voice message... Please speak.")
                audio = r.listen(source)
            try:
                transcription = r.recognize_google(audio)
                self.update_chat_area("Voice message transcribed: " + transcription)
                return transcription
            except sr.UnknownValueError:
                self.update_chat_area("Could not understand the voice message.")
                return ""
            except sr.RequestError as e:
                self.update_chat_area("Error with transcription service.")
                return ""
        except Exception as e:
            self.update_chat_area("Error recording voice message: " + str(e))
            return ""

    def send_voice_message(self):
        transcription = self.record_voice_message()
        if transcription:
            self.text_input.delete(0, tk.END)
            self.text_input.insert(0, transcription)
            self.send_message()

    def speak_text(self, text):
        engine = pyttsx3.init()
        engine.say(text)
        engine.runAndWait()


def show_disclaimer():
    disclaimer_text = (
        "DISCLAIMER:\n\n"
        "This software is intended for educational and lawful use only. "
        "Any misuse of this encryption technology for illegal or unethical purposes is strongly discouraged. "
        "Users are responsible for complying with all applicable laws and regulations in their jurisdiction."
    )
    messagebox.showinfo("Disclaimer", disclaimer_text)


if __name__ == "__main__":
    root = tk.Tk()
    show_disclaimer()
    client_app = OTPClient(root)
    root.mainloop()
