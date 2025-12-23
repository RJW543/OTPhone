import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox, scrolledtext
import tkinter.simpledialog
import socket
import threading
from pathlib import Path
import fcntl
import speech_recognition as sr
import pyttsx3


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

#OTPClient class
class OTPClient:
    def __init__(self, master):
        self.master = master
        self.master.title("OTP Messaging Client")

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

        ttk.Label(self.message_frame, text="Recipient userID:").grid(row=2, column=0, padx=5, sticky="e")
        self.recipient_input = ttk.Entry(self.message_frame, width=40)
        self.recipient_input.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(self.message_frame, text="Message:").grid(row=3, column=0, padx=5, sticky="e")
        self.text_input = ttk.Entry(self.message_frame, width=40)
        self.text_input.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        self.send_button = ttk.Button(self.message_frame, text="Send Text Message", command=self.send_message)
        self.send_button.grid(row=4, column=0, padx=5, pady=5, sticky="e")

        self.record_button = ttk.Button(self.message_frame, text="Record Voice Message", command=self.send_voice_message)
        self.record_button.grid(row=4, column=1, padx=5, pady=5, sticky="w")

        for child in self.message_frame.winfo_children():
            child.grid_remove()

    def show_about_info(self):
        messagebox.showinfo("About", "OTP Messaging Client\nVersion 1.4\nUsing Tkinter & Python.")

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
                 #Check if the client socket is active and receive data
                if self.client_socket:
                    data = self.client_socket.recv(4096)
                    if not data: #If no data is received, exit the loop
                        break
                    message = data.decode("utf-8") #Decode the received message
                    try:
                        #Parse the received message into sender ID and payload
                        sender_id, payload = message.split("|", 1)
                        otp_identifier, actual_encrypted_message = payload.split(":", 1)

                        #Search for the OTP content corresponding to the identifier
                        otp_content = None
                        for identifier, content in self.otp_pages:
                            if identifier == otp_identifier:
                                otp_content = content
                                break

                        if otp_content:
                            #Decrypt the message using the OTP content
                            decrypted_message = decrypt_message(actual_encrypted_message, otp_content)
                            display_line = f"Received from {sender_id} (Decrypted): {decrypted_message}"
                            self.update_chat_area(display_line)
                            #Use a separate thread to speak the decrypted message
                            threading.Thread(target=self.speak_text, args=(decrypted_message,), daemon=True).start()
                            #Mark the OTP page as used and save it
                            save_used_page(otp_identifier)
                            self.used_identifiers.add(otp_identifier)
                        else:
                            #Handle case where OTP identifier is unknown
                            display_line = f"Received from {sender_id} (Unknown OTP): {actual_encrypted_message}"
                            self.update_chat_area(display_line)
                    except ValueError:
                        #Handle improperly formatted messages
                        self.update_chat_area("Received an improperly formatted message.")
            except Exception as e:
                #Log any errors that occur during message reception
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
