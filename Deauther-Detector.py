import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
import base64
import io
import threading
import queue
from datetime import datetime, timedelta
import subprocess
import sys

# Base64 encoded anonymous background image (simple pattern)
BG_IMAGE_BASE64 = """
iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAAAAXNSR0IArs4c6QAAAARnQU1BAACx
jwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAABOSURBVGhD7cExAQAwDMCg+zfd2fAqEPmTkpKS
kpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKSkpKS8g55ASusA8kA
AAAASUVORK5CYII=
"""

class DeauthDetectorGUI:
    def __init__(self, master):
        self.master = master
        master.title("Deauth Detector + Honeypot")
        master.geometry("1000x700")
        
        # Create background image
        self.create_background()
        
        # Main container frame (on top of background)
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(fill="both", expand=True)
        
        # Rest of your initialization code...
        self.data_queue = queue.Queue()
        self.detection_active = False
        # ... (rest of your existing __init__ code)

    def create_background(self):
        # Decode base64 image
        image_data = base64.b64decode(BG_IMAGE_BASE64)
        image = Image.open(io.BytesIO(image_data))
        
        # Resize to window dimensions
        self.bg_image = ImageTk.PhotoImage(image.resize((1000, 700), Image.Resampling.LANCZOS))
        
        # Create background label
        self.bg_label = tk.Label(self.master, image=self.bg_image)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        
        # Make sure it stays in background
        self.bg_label.lower()

    def setup_gui(self):
        # Now setup all your widgets on self.main_frame instead of self.master
        self.status_frame = ttk.LabelFrame(self.main_frame, text="Status", padding=10)
        self.status_frame.pack(fill="x", padx=10, pady=5)
        
        # ... (rest of your existing setup_gui code, 
        # just change self.master to self.main_frame where needed)

    # ... (rest of your existing methods)

def main():
    root = tk.Tk()
    app = DeauthDetectorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
