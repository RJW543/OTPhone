import tkinter as tk
from tkinter import messagebox
import threading
import socket
import socketserver
from pyngrok import ngrok
import json
from Crypto.Random import get_random_bytes

clients = {}  # {user_id: client_socket}
aes_clients = {}  # {user_id: client_socket} - specifically for AES clients
session_keys = {}  # {(user_id1, user_id2): shared_key} - keys for AES pairs

def get_or_create_session_key(user1, user2):
    """Get or create a shared session key for two users."""
    # Create a sorted tuple to ensure consistent key lookup
    key_pair = tuple(sorted([user1, user2]))
    
    if key_pair not in session_keys:
        # Generate a new 256-bit (32-byte) AES key
        new_key = get_random_bytes(32)
        session_keys[key_pair] = new_key
        print(f"Generated new session key for {user1} <-> {user2}")
    
    return session_keys[key_pair]

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        client_socket = self.request
        user_id = None
        is_aes_client = False
        
        try:
            #Receive the userID upon connect
            initial_message = client_socket.recv(1024).decode("utf-8").strip()
            
            # Check if this is an AES client
            if initial_message.startswith("AES:"):
                is_aes_client = True
                user_id = initial_message[4:]  # Remove "AES:" prefix
            else:
                user_id = initial_message
            
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
            if is_aes_client:
                aes_clients[user_id] = client_socket
            
            client_socket.sendall("Connected successfully.".encode("utf-8"))
            print(f"User '{user_id}' connected from {self.client_address} (AES: {is_aes_client})")

            #Handle incoming messages from this client
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break  
                message = data.decode("utf-8")

                # Handle AES key requests
                if message.startswith("AESKEY:"):
                    key_request_data = json.loads(message[7:])
                    recipient_id = key_request_data["recipient"]
                    
                    # Generate or retrieve the session key for this pair
                    session_key = get_or_create_session_key(user_id, recipient_id)
                    
                    # Send the key to the requesting client
                    key_response = json.dumps({
                        "recipient": recipient_id,
                        "key": session_key.hex()
                    })
                    client_socket.sendall(f"KEYEXCHANGE:{key_response}".encode("utf-8"))
                    print(f"Sent session key to '{user_id}' for communication with '{recipient_id}'")
                    
                    # Also send the key to the recipient if they're connected and an AES client
                    if recipient_id in aes_clients:
                        recipient_socket = aes_clients[recipient_id]
                        recipient_key_response = json.dumps({
                            "recipient": user_id,
                            "key": session_key.hex()
                        })
                        try:
                            recipient_socket.sendall(f"KEYEXCHANGE:{recipient_key_response}".encode("utf-8"))
                            print(f"Sent session key to '{recipient_id}' for communication with '{user_id}'")
                        except Exception as e:
                            print(f"Failed to send key to '{recipient_id}': {e}")
                    
                    continue

                # Handle regular message forwarding
                try:
                    recipient_id, encrypted_message = message.split("|", 1)
                    print(f"Received message for '{recipient_id}' from '{user_id}'")
                    send_message_to_recipient(recipient_id, encrypted_message, user_id)
                except ValueError:
                    client_socket.sendall("Invalid message format.".encode("utf-8"))

        except Exception as e:
            print(f"Error handling client {self.client_address}: {e}")
        finally:
            if user_id:
                if user_id in clients:
                    del clients[user_id]
                if user_id in aes_clients:
                    del aes_clients[user_id]
                
                # Clean up session keys involving this user
                keys_to_remove = [key_pair for key_pair in session_keys.keys() if user_id in key_pair]
                for key_pair in keys_to_remove:
                    del session_keys[key_pair]
                    print(f"Removed session key for {key_pair}")
                
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
            if recipient_id in clients:
                del clients[recipient_id]
            if recipient_id in aes_clients:
                del aes_clients[recipient_id]
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
        self.master.title("OTP Server GUI")

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
                    print("Server supports both OTP and AES (auto key exchange) clients.")
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

        #Clear session keys
        global session_keys
        session_keys = {}
        print("Cleared all session keys.")

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