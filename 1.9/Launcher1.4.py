import tkinter as tk
import subprocess
import sys
from tkinter import messagebox

class MainMenuApp:
    def __init__(self, master):
        self.master = master
        self.master.title("OTP Main Menu v1.5")

        #Label / Title
        tk.Label(master, text="OTP Messaging System", font=("Arial", 16, "bold")).pack(pady=10)
        tk.Label(master, text="Please choose an action:", font=("Arial", 12)).pack(pady=5)

        #Buttons
        btn_host_server = tk.Button(master, text="Host Server", width=25, height=2, command=self.launch_server_gui)
        btn_host_server.pack(pady=5)

        btn_run_client = tk.Button(master, text="Run Client", width=25, height=2, command=self.launch_client_gui)
        btn_run_client.pack(pady=5)

        btn_generate_otp = tk.Button(master, text="Generate a new OTP", width=25, height=2, command=self.launch_gen_gui)
        btn_generate_otp.pack(pady=5)
        
        # Version info
        tk.Label(
            master, 
            text="v1.5 - Hardware RNG + Bluetooth OTP Sharing", 
            font=("Arial", 8),
            fg="gray"
        ).pack(pady=10)

    def launch_server_gui(self):
        """
        Launch TextASG1_4.py (the server GUI).
        """
        try:
            subprocess.Popen([sys.executable, "TextASG1_4.py"])
        except FileNotFoundError:
            messagebox.showerror("Error", "Could not find or launch TextASG1_4.py")

    def launch_client_gui(self):
        """
        Launch VoiceAC1_5.py (the client GUI with Bluetooth support).
        """
        try:
            subprocess.Popen([sys.executable, "VoiceAC1_5.py"])
        except FileNotFoundError:
            messagebox.showerror("Error", "Could not find or launch VoiceAC1_5.py")

    def launch_gen_gui(self):
        """
        Launch GenGUI1_5.py (the OTP generator GUI with hardware RNG).
        """
        try:
            subprocess.Popen([sys.executable, "GenGUI1_5.py"])
        except FileNotFoundError:
            messagebox.showerror("Error", "Could not find or launch GenGUI1_5.py")


def main():
    root = tk.Tk()
    app = MainMenuApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()