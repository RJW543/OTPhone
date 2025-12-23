import tkinter as tk
from tkinter import messagebox
import threading
import socket
import socketserver
from pyngrok import ngrok

# --- v1.5 additions: AES + OTP-Lite protocol support ---
import json
import base64
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

clients = {}

# Stores per-user public keys for server-assisted OTP-Lite delivery.
# Keys are registered by the client after connecting.
client_rsa_pubs = {}  # user_id -> cryptography public key

SERVER_USER_ID = "__server__"
MAX_OTPLITE_LEN = 1024  # bytes; keeps messages within a single TCP recv() in this simple demo


def _safe_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None


def _send_system_message(target_user_id: str, payload: dict):
    """Send a server-originated JSON payload to a connected client."""
    sock = clients.get(target_user_id)
    if not sock:
        return
    try:
        msg = f"{SERVER_USER_ID}|{json.dumps(payload, separators=(',', ':'))}"
        sock.sendall(msg.encode("utf-8"))
    except Exception:
        try:
            sock.close()
        finally:
            clients.pop(target_user_id, None)
            client_rsa_pubs.pop(target_user_id, None)


def _encrypt_bytes_for_client(plain: bytes, rsa_pub) -> dict:
    """Hybrid encrypt: RSA-OAEP encrypts a random AES key, AES-GCM encrypts the data."""
    aes_key = secrets.token_bytes(32)
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plain, None)
    ek = rsa_pub.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "ek": base64.b64encode(ek).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


def _handle_server_command(sender_id: str, payload: dict):
    """Handle messages addressed to __server__ for OTP-Lite and key registration."""
    if not isinstance(payload, dict):
        _send_system_message(sender_id, {"t": "ERROR", "msg": "Invalid server command payload."})
        return

    t = payload.get("t")

    # Client registers RSA public key for OTP-Lite delivery.
    if t == "REGISTER_KEYS":
        rsa_pub_b64 = payload.get("rsa_pub")
        if not rsa_pub_b64:
            _send_system_message(sender_id, {"t": "ERROR", "msg": "Missing rsa_pub."})
            return
        try:
            pem = base64.b64decode(rsa_pub_b64.encode("ascii"))
            pub = serialization.load_pem_public_key(pem)
            client_rsa_pubs[sender_id] = pub
            _send_system_message(sender_id, {"t": "KEYS_OK"})
        except Exception as e:
            _send_system_message(sender_id, {"t": "ERROR", "msg": f"Failed to register keys: {e}"})
        return

    # OTP-Lite request: server generates a one-time pad for a single message.
    if t == "OTPLITE_REQUEST":
        to_user = payload.get("to")
        msg_id = payload.get("msg_id")
        length = payload.get("length")

        if not to_user or not msg_id or not isinstance(length, int) or length <= 0:
            _send_system_message(sender_id, {"t": "ERROR", "msg": "Invalid OTPLITE_REQUEST."})
            return

        if length > MAX_OTPLITE_LEN:
            _send_system_message(sender_id, {"t": "ERROR", "msg": f"OTP-Lite message too long (max {MAX_OTPLITE_LEN} bytes). Use AES for longer messages."})
            return

        if to_user not in clients:
            _send_system_message(sender_id, {"t": "ERROR", "msg": f"Recipient '{to_user}' not connected."})
            return

        sender_pub = client_rsa_pubs.get(sender_id)
        recipient_pub = client_rsa_pubs.get(to_user)
        if not sender_pub or not recipient_pub:
            _send_system_message(
                sender_id,
                {"t": "ERROR", "msg": "OTP-Lite requires both clients to have registered RSA keys."},
            )
            return

        # Generate pseudorandom pad bytes (OTP-Lite) and deliver it encrypted to both clients.
        pad_bytes = secrets.token_bytes(length)
        try:
            sender_pack = _encrypt_bytes_for_client(pad_bytes, sender_pub)
            recipient_pack = _encrypt_bytes_for_client(pad_bytes, recipient_pub)

            common = {"t": "OTPLITE_PAD", "msg_id": msg_id, "from": sender_id, "to": to_user, "length": length}
            _send_system_message(sender_id, {**common, **sender_pack})
            _send_system_message(to_user, {**common, **recipient_pack})
        finally:
            # Ensure pad isn't kept server-side.
            pad_bytes = None
        return

    _send_system_message(sender_id, {"t": "ERROR", "msg": f"Unknown server command: {t}"})

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_socket = self.request
        user_id = None
        try:
            #Receive the userID upon connect
            user_id = client_socket.recv(1024).decode("utf-8").strip()
            if not user_id:
                client_socket.sendall("Invalid userID. Connection closed.".encode("utf-8"))
                client_socket.close()
                return

            if user_id in clients:
                client_socket.sendall("UserID already taken. Connection closed.".encode("utf-8"))
                client_socket.close()
                print(f"Rejected connection from {self.client_address}: UserID '{user_id}' already taken.")
                return

            #Register the client
            clients[user_id] = client_socket
            client_socket.sendall("Connected successfully.".encode("utf-8"))
            print(f"User '{user_id}' connected from {self.client_address}")

            #Handle incoming messages from this client
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break  
                message = data.decode("utf-8")

                try:
                    recipient_id, payload_str = message.split("|", 1)
                except ValueError:
                    client_socket.sendall("Invalid message format.".encode("utf-8"))
                    continue

                # Messages addressed to __server__ are commands (key registration, OTP-Lite pad requests).
                if recipient_id == SERVER_USER_ID:
                    payload = _safe_json_loads(payload_str)
                    _handle_server_command(user_id, payload)
                    continue

                print(f"Received message for '{recipient_id}' from '{user_id}': {payload_str}")
                send_message_to_recipient(recipient_id, payload_str, user_id)

        except Exception as e:
            print(f"Error handling client {self.client_address}: {e}")
        finally:
            if user_id and user_id in clients:
                del clients[user_id]
                client_rsa_pubs.pop(user_id, None)
                print(f"User '{user_id}' disconnected.")
            client_socket.close()

def send_message_to_recipient(recipient_id, message, sender_id):
    recipient_socket = clients.get(recipient_id)
    if recipient_socket:
        try:
            full_message = f"{sender_id}|{message}"
            recipient_socket.sendall(full_message.encode("utf-8"))
            print(f"Forwarded message from '{sender_id}' to '{recipient_id}'.")
        except Exception as e:
            print(f"Failed to send message to '{recipient_id}': {e}")
            del clients[recipient_id]
            client_rsa_pubs.pop(recipient_id, None)
            recipient_socket.close()
    else:
        #Notify the sender that the recipient doesn't exist
        sender_socket = clients.get(sender_id)
        if sender_socket:
            msg = f"Recipient '{recipient_id}' not found."
            sender_socket.sendall(msg.encode("utf-8"))
            print(f"User '{sender_id}' tried to send message to unknown recipient '{recipient_id}'.")

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

class ServerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("OTP Server GUI (v1.5)")

        self.HOST = "0.0.0.0"
        self.PORT = 65432

        self.server = None
        self.server_thread = None
        self.ngrok_tunnel = None

        #Status label
        self.status_label = tk.Label(master, text="Server is NOT running.", fg="red", font=("Arial", 12))
        self.status_label.pack(pady=5)

        #Start Button
        self.start_button = tk.Button(master, text="Start Server", command=self.start_server, width=15)
        self.start_button.pack(pady=5)

        #Label to display the public NGROK info
        self.ngrok_info_label = tk.Label(master, text="", fg="blue", font=("Arial", 10))
        self.ngrok_info_label.pack(pady=5)

        #Stop Button
        self.stop_button = tk.Button(master, text="Stop Server", command=self.stop_server, width=15, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

    def start_server(self):
        """Starts the Ngrok tunnel and the ThreadedTCPServer in a background thread."""
        try:
            #Open the pyngrok tunnel
            self.ngrok_tunnel = ngrok.connect(self.PORT, "tcp")
            public_url = self.ngrok_tunnel.public_url  

            #Parse host and port from the public URL
            parsed_url = public_url.replace("tcp://", "").split(":")
            ngrok_host = parsed_url[0]
            ngrok_port = parsed_url[1]

            #Update the label to show the ngrok info
            self.ngrok_info_label.config(
                text=f"Public URL: {public_url}\nNgrok Host: {ngrok_host}\nNgrok Port: {ngrok_port}"
            )

            #Define the server thread
            def run_server():
                self.server = ThreadedTCPServer((self.HOST, self.PORT), ThreadedTCPRequestHandler)
                with self.server:
                    ip, port = self.server.server_address
                    print(f"Local server running on {ip}:{port}.")
                    self.server.serve_forever()

            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()

            #Update status
            self.status_label.config(text="Server is RUNNING.", fg="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Error starting server", str(e))

    def stop_server(self):
        """Stops the server and closes the ngrok tunnel."""
        if self.server:
            try:
                #Shut down the server
                self.server.shutdown()
                self.server.server_close()
                print("Server has been stopped.")
            except Exception as e:
                print(f"Error stopping server: {e}")

        #Disconnect the ngrok tunnel if it is open
        if self.ngrok_tunnel:
            try:
                ngrok.disconnect(self.ngrok_tunnel.public_url)
                print("Ngrok tunnel disconnected.")
            except Exception as e:
                print(f"Error disconnecting ngrok tunnel: {e}")

        #Reset references
        self.server = None
        self.server_thread = None
        self.ngrok_tunnel = None

        #Update status
        self.status_label.config(text="Server is NOT running.", fg="red")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.ngrok_info_label.config(text="")

def main():
    root = tk.Tk()
    gui = ServerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
