import tkinter as tk
from tkinter import messagebox
import threading
import socket
import socketserver
from pyngrok import ngrok

clients = {}  

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
                    recipient_id, encrypted_message = message.split("|", 1)
                    print(f"Received message for '{recipient_id}' from '{user_id}': {encrypted_message}")
                    send_message_to_recipient(recipient_id, encrypted_message, user_id)
                except ValueError:
                    client_socket.sendall("Invalid message format.".encode("utf-8"))

        except Exception as e:
            print(f"Error handling client {self.client_address}: {e}")
        finally:
            if user_id and user_id in clients:
                del clients[user_id]
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
