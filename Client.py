import customtkinter
import tkinter as tk
from PIL import Image
import os
from tkinter import filedialog
from tkinter import messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15 as Signature_pkcs1_15
from Crypto.Hash import SHA256
import base64

customtkinter.set_appearance_mode("dark")


class App(customtkinter.CTk):
    width = 900
    height = 600

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.title("CustomTkinter example_background_image.py")
        self.geometry(f"{self.width}x{self.height}")
        self.resizable(False, False)

        # load and create background image
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Images")
        self.bg_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "prepanetlogo.jpg")),
                                               size=(self.width, self.height))
        self.bg_image_label = customtkinter.CTkLabel(self, image=self.bg_image)
        self.bg_image_label.grid(row=0, column=0)

        # create login frame
        self.login_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.login_frame.grid(row=0, column=0, sticky="ns")
        self.login_label = customtkinter.CTkLabel(self.login_frame, text="Ventana de verificacion",
                                                  font=customtkinter.CTkFont(size=20, weight="bold"))
        self.login_label.grid(row=0, column=0, padx=30, pady=(150, 15))
        self.file_path = tk.StringVar()
        file_label = customtkinter.CTkLabel(self.login_frame, text="PDF File:")
        file_label.grid()
        self.file_entry = customtkinter.CTkEntry(self.login_frame, textvariable=self.file_path)
        self.file_entry.grid()
        file_button = customtkinter.CTkButton(self.login_frame, text="Browse", command=self.browse_file)
        file_button.grid()

        self.sign_path = tk.StringVar()
        sign_label = customtkinter.CTkLabel(self.login_frame, text="Signature Image:")
        sign_label.grid()
        self.sign_path_entry = customtkinter.CTkEntry(self.login_frame, textvariable=self.sign_path)
        self.sign_path_entry.grid()
        sign_button = customtkinter.CTkButton(self.login_frame, text="Browse", command=self.browse_signature_verify)
        sign_button.grid()
        


        self.public_key_path = tk.StringVar()
        public_key_label = customtkinter.CTkLabel(self.login_frame, text="Public Key:")
        public_key_label.grid()
        self.public_key_entry = customtkinter.CTkEntry(self.login_frame, textvariable=self.public_key_path)
        self.public_key_entry.grid()
        public_key_button = customtkinter.CTkButton(self.login_frame, text="Browse", command=self.browse_public_key)
        public_key_button.grid()

        verify_button = customtkinter.CTkButton(self.login_frame, text="Verify", command=self.verify)
        verify_button.grid()

        # create main frame
        self.main_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_label = customtkinter.CTkLabel(self.main_frame, text="Ventana de verificacion",
                                                 font=customtkinter.CTkFont(size=20, weight="bold"))
        self.main_label.grid(row=0, column=0, padx=30, pady=(30, 15))

    def browse_file(self):
        file_path_v = filedialog.askopenfilename(filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
        self.file_path.set(file_path_v)


    def browse_public_key(self):
        public_key_path_v = filedialog.askopenfilename(filetypes=(("Public Key files", "*.pem"), ("All files", "*.*")))
        self.public_key_path.set(public_key_path_v)

    def browse_signature_verify(self):
        siganture_path_ver = filedialog.askopenfilename(filetypes=(("signature files", "*.txt"), ("All files", "*.*")))
        self.sign_path.set(siganture_path_ver)

    def verify(self):
        file_path = self.file_path.get()
        public_key_path = self.public_key_path.get()
        signature_path = self.sign_path.get()  

        if not public_key_path or not file_path:
            messagebox.showerror("Error", "Please provide all file paths.")
            return

        try:
            with open(file_path, 'rb') as file:
                pdf = file.read()
                
                public_key_pem = RSA.import_key(open(public_key_path, 'rb').read())
                hash_obj = SHA256.new(pdf)
                verifier = Signature_pkcs1_15.new(public_key_pem).verify(hash_obj, base64.b64decode(signature_path))

                if verifier:
                    messagebox.showinfo("Success", "Signature is valid.")
                else:
                   messagebox.showwarning("Warning", "Signature is not valid.")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def back_event(self):
        self.main_frame.grid_forget()  
        self.login_frame.grid(row=0, column=0, sticky="ns")  


if __name__ == "__main__":
    app = App()
    app.mainloop()