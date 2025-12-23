import tkinter as tk
from tkinter import messagebox, scrolledtext
import requests
import random
import string
from pathlib import Path
import threading

# Try to import hardware RNG
try:
    from HardwareRNG import HardwareRandomGenerator
    HARDWARE_RNG_AVAILABLE = True
except ImportError:
    HARDWARE_RNG_AVAILABLE = False
    print("Warning: HardwareRNG module not found")

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

def generate_otp_page_hardware(hw_rng, identifier_length=8, page_length=3500):
    """
    Generate a single OTP page using hardware random number generator.
    
    Args:
        hw_rng: HardwareRandomGenerator instance
        identifier_length: Length of page identifier
        page_length: Total page length
        
    Returns:
        str: OTP page
    """
    chars = string.ascii_uppercase + string.digits + string.punctuation
    
    # Generate identifier
    identifier = hw_rng.generate_random_string(identifier_length, chars)
    
    # Generate OTP content
    otp_content = hw_rng.generate_random_string(page_length - identifier_length, chars)
    
    return identifier + otp_content

def generate_otp_file(file_name="otp_cipher.txt", num_pages=10000, mode="standard", callback=None):
    """
    Generate an OTP file with each page on a new line.
    Mode can be 'standard', 'fast', or 'hardware'.
    The page length is fixed at 3500 characters.
    
    Args:
        file_name: Output file name
        num_pages: Number of pages to generate
        mode: Generation mode
        callback: Optional callback for status updates
    """
    page_length = 3500

    def log(msg):
        if callback:
            callback(msg)
        else:
            print(msg)

    if mode == "standard":
        log("Mode: Standard (Random.org seed)")
        #Fetch a true random seed from Random.org
        random_seed = fetch_random_seed()
        random.seed(random_seed)
        log(f"Random seed obtained from Random.org")
        
    elif mode == "fast":
        log("Mode: Fast (System time seed)")
        # Just use Python's built-in seeding (system time)
        random.seed()
        
    elif mode == "hardware":
        if not HARDWARE_RNG_AVAILABLE:
            raise ImportError("Hardware RNG module not available")
        log("Mode: Hardware (Camera + Microphone + System sensors)")
        log("This will use your device's camera and microphone for true randomness")

    output_path = Path(file_name)
    
    if mode == "hardware":
        # Use hardware-based generation
        hw_rng = HardwareRandomGenerator(callback=log)
        
        with output_path.open("w", encoding="utf-8") as file:
            for i in range(num_pages):
                # Collect fresh entropy for each page for maximum randomness
                # Use fewer frames/shorter duration per page to speed up
                otp_page = generate_otp_page_hardware(hw_rng, page_length=page_length)
                file.write(otp_page + "\n")
                
                if (i + 1) % 10 == 0:
                    log(f"Generated {i + 1}/{num_pages} pages...")
    else:
        # Use pseudorandom generation (seeded)
        with output_path.open("w", encoding="utf-8") as file:
            for i in range(num_pages):
                otp_page = generate_otp_page(page_length=page_length)
                file.write(otp_page + "\n")
                
                if (i + 1) % 1000 == 0:
                    log(f"Generated {i + 1}/{num_pages} pages...")

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
        modes_frame = tk.LabelFrame(master, text="Generation Mode")
        modes_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

        tk.Radiobutton(
            modes_frame, 
            text="Standard (Random.org seed)", 
            variable=self.mode_var, 
            value="standard"
        ).pack(anchor="w")
        
        tk.Radiobutton(
            modes_frame, 
            text="Fast (System time seed)", 
            variable=self.mode_var, 
            value="fast"
        ).pack(anchor="w")
        
        hw_text = "Hardware (Camera + Mic + Sensors) - TRUE RANDOM"
        if not HARDWARE_RNG_AVAILABLE:
            hw_text += " [NOT AVAILABLE]"
        
        self.hw_radio = tk.Radiobutton(
            modes_frame, 
            text=hw_text, 
            variable=self.mode_var, 
            value="hardware"
        )
        self.hw_radio.pack(anchor="w")
        
        if not HARDWARE_RNG_AVAILABLE:
            self.hw_radio.config(state=tk.DISABLED)

        # Info label
        info_text = (
            "Hardware mode uses your device's camera, microphone, and sensors\n"
            "to generate cryptographically secure true random numbers.\n"
            "This is the most secure option for OTP generation."
        )
        self.info_label = tk.Label(master, text=info_text, fg="blue", font=("Arial", 8), justify=tk.LEFT)
        self.info_label.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        #Generate Button
        generate_button = tk.Button(master, text="Generate OTP File", command=self.generate_otp_action)
        generate_button.grid(row=4, column=0, columnspan=2, padx=5, pady=10)

        #Status Label
        self.status_label = tk.Label(master, text="", fg="green")
        self.status_label.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def generate_otp_action(self):
        file_name = "otp_cipher.txt"

        #Validate num_pages
        try:
            num_pages = int(self.num_pages_var.get().strip())
        except ValueError:
            messagebox.showerror("Error", "Number of OTP pages must be an integer.")
            return

        selected_mode = self.mode_var.get()

        # For hardware mode, show a progress window
        if selected_mode == "hardware":
            self.generate_hardware_mode(file_name, num_pages)
        else:
            # Standard or fast mode
            try:
                self.status_label.config(text="Generating OTP file...")
                self.master.update()
                
                output_path = generate_otp_file(
                    file_name=file_name,
                    num_pages=num_pages,
                    mode=selected_mode
                )
                self.status_label.config(text=f"✓ Generated {num_pages} pages to '{output_path}'.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate OTP file:\n{e}")
                self.status_label.config(text="")
    
    def generate_hardware_mode(self, file_name, num_pages):
        """Generate OTP using hardware mode with progress window."""
        # Create progress window
        progress_window = tk.Toplevel(self.master)
        progress_window.title("Hardware OTP Generation")
        progress_window.geometry("600x400")
        
        tk.Label(
            progress_window, 
            text="Generating True Random OTP using Hardware", 
            font=("Arial", 12, "bold")
        ).pack(pady=10)
        
        tk.Label(
            progress_window,
            text="This uses your camera, microphone, and system sensors.\nPlease wait...",
            fg="blue"
        ).pack(pady=5)
        
        # Status text area
        status_text = scrolledtext.ScrolledText(
            progress_window, 
            width=70, 
            height=20, 
            state=tk.DISABLED
        )
        status_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        def log_status(message):
            """Add message to status window."""
            status_text.config(state=tk.NORMAL)
            status_text.insert(tk.END, message + "\n")
            status_text.config(state=tk.DISABLED)
            status_text.yview(tk.END)
            progress_window.update()
        
        def do_generation():
            """Run generation in thread."""
            try:
                output_path = generate_otp_file(
                    file_name=file_name,
                    num_pages=num_pages,
                    mode="hardware",
                    callback=log_status
                )
                
                log_status("=" * 50)
                log_status(f"✓ SUCCESS! Generated {num_pages} pages")
                log_status(f"✓ Saved to: {output_path}")
                log_status("=" * 50)
                
                self.status_label.config(text=f"✓ Generated {num_pages} pages using HARDWARE RNG")
                
                # Add close button
                def close_window():
                    progress_window.destroy()
                
                close_btn = tk.Button(
                    progress_window, 
                    text="Close", 
                    command=close_window,
                    bg="green",
                    fg="white",
                    font=("Arial", 10, "bold")
                )
                close_btn.pack(pady=10)
                
            except Exception as e:
                log_status(f"✗ ERROR: {e}")
                messagebox.showerror("Error", f"Failed to generate OTP file:\n{e}")
                progress_window.destroy()
        
        # Start generation in background thread
        gen_thread = threading.Thread(target=do_generation, daemon=True)
        gen_thread.start()

def main():
    root = tk.Tk()
    app = OTPGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()