import tkinter as tk
from tkinter import messagebox
import requests
import random
import string
from pathlib import Path

API_KEY = 'e02643a9-6574-4a3a-b2a8-14b7c13d80c5'

def fetch_random_seed():
    """Fetch a random seed from Random.org."""
    url = "https://api.random.org/json-rpc/4/invoke"
    headers = {'Content-Type': 'application/json'}
    data = {
        "jsonrpc": "2.0",
        "method": "generateStrings",
        "params": {
            "apiKey": API_KEY,
            "n": 1,
            "length": 32,
            "characters": string.ascii_uppercase + string.digits + string.punctuation,
            "replacement": True
        },
        "id": 1
    }

    response = requests.post(url, json=data, headers=headers)
    response_data = response.json()

    #If there's an error from Random.org
    if "error" in response_data:
        raise ValueError(f"Random.org API error: {response_data['error']['message']}")
    return response_data['result']['random']['data'][0]

def generate_random_string(length):
    """Generate a random string using the currently-seeded pseudorandom generator."""
    chars = string.ascii_uppercase + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

def generate_otp_page(identifier_length=8, page_length=3500):
    """
    Generate a single OTP page with a random identifier and OTP content.
    Note: The random module should already be seeded before calling.
    """
    identifier = generate_random_string(identifier_length)
    otp_content = generate_random_string(page_length - identifier_length)
    return identifier + otp_content

def generate_otp_file(file_name="otp_cipher.txt", num_pages=10000, mode="standard"):
    """
    Generate an OTP file with each page on a new line.
    Mode can be 'standard', 'fast', or 'advanced'.
    The page length is fixed at 3500 characters.
    """
    page_length = 3500  

    if mode == "standard":
        #Fetch a true random seed from Random.org
        random_seed = fetch_random_seed()
        random.seed(random_seed)
    elif mode == "fast":
        # ust use Python's built-in seeding (system time)
        random.seed()


    output_path = Path(file_name)
    with output_path.open("w", encoding="utf-8") as file:
        for _ in range(num_pages):
            otp_page = generate_otp_page(page_length=page_length)
            file.write(otp_page + "\n")

    return output_path.resolve()


class OTPGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("OTP File Generator")

        #Output file name is locked to "otp_cipher.txt"
        tk.Label(master, text="Output File Name (fixed): otp_cipher.txt").grid(
            row=0, column=0, columnspan=2, padx=5, pady=5
        )

        #Number of Pages
        tk.Label(master, text="Number of OTP Pages:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.num_pages_var = tk.StringVar(value="10000")
        tk.Entry(master, textvariable=self.num_pages_var, width=10).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        #Mode Selection
        self.mode_var = tk.StringVar(value="standard")  
        modes_frame = tk.LabelFrame(master, text="Mode")
        modes_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        tk.Radiobutton(modes_frame, text="Standard", variable=self.mode_var, value="standard").pack(anchor="w")
        tk.Radiobutton(modes_frame, text="Fast", variable=self.mode_var, value="fast").pack(anchor="w")
        tk.Radiobutton(modes_frame, text="Advanced", variable=self.mode_var, value="advanced").pack(anchor="w")

        #Generate Button
        generate_button = tk.Button(master, text="Generate OTP File", command=self.generate_otp_action)
        generate_button.grid(row=3, column=0, columnspan=2, padx=5, pady=10)

        #Status Label
        self.status_label = tk.Label(master, text="", fg="blue")
        self.status_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    def generate_otp_action(self):
        file_name = "otp_cipher.txt"

        #Validate num_pages
        try:
            num_pages = int(self.num_pages_var.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Number of OTP pages must be an integer.")
            return

        selected_mode = self.mode_var.get()  #"standard", "fast", or "advanced"

        #If advanced mode is chosen, do nothing but show a message
        if selected_mode == "advanced":
            messagebox.showinfo("Not yet implemented", "Advanced mode is not yet implemented.")
            return  

        #Otherwise, generate the file
        try:
            output_path = generate_otp_file(
                file_name=file_name,
                num_pages=num_pages,
                mode=selected_mode
            )
            self.status_label.config(text=f"Generated {num_pages} pages to '{output_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate OTP file:\n{e}")

def main():
    root = tk.Tk()
    app = OTPGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()