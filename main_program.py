import tkinter as tk
import customtkinter
from tkinter import filedialog
from tkinter import messagebox
from PIL import Image
import os
from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Signature import pkcs1_15 as Signature_pkcs1_15
from base64 import b64encode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
from datetime import datetime
import random
import PDFNetPython3.PDFNetPython as PDFNet
import zipfile
#from PDFNetPython3.PDFNetPython import *

customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("dark-blue")

class DigitalSignatureGUI(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Digital Signature")
        self.geometry("800x450")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        image_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "Images")
        self.logo_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "prepanetlogo.jpg")), size=(100, 100))
        self.home_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "Home.jpg")), size=(20, 20))
        self.esign_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "Sig.jpg")), size=(20, 20))
        self.cert_image = customtkinter.CTkImage(Image.open(os.path.join(image_path, "cert_img.jpg")), size=(20,20))


        self.navigation_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.navigation_frame.grid(row=0, column=0, sticky="nsew")
        self.navigation_frame.grid_rowconfigure(4, weight=1)

        self.navigation_frame_label = customtkinter.CTkLabel(self.navigation_frame, text="Prepa Net", image=self.logo_image,
                                                             compound="left", font=customtkinter.CTkFont(size=15, weight="bold"))
        
        self.navigation_frame_label.grid(row=0, column=0, padx=20, pady=20)

        self.home_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Home",
                                                   fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                   image=self.home_image, anchor="w", command=self.home_button_event)
        
        self.home_button.grid(row=1, column=0, sticky="ew")

        self.frame_2_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Proceso de firma digital",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.esign_image, anchor="w", command=self.frame_2_button_event)
        
        self.frame_2_button.grid(row=2, column=0, sticky="ew")

        self.frame_3_button = customtkinter.CTkButton(self.navigation_frame, corner_radius=0, height=40, border_spacing=10, text="Proceso de firma digital con certificados",
                                                      fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"),
                                                      image=self.cert_image ,anchor="w", command=self.frame_3_button_event)
        
        self.frame_3_button.grid(row=3, column=0, sticky="ew")
        #---------------------------------------------------------------------------------------------------------

        self.home_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.home_frame.grid_columnconfigure(0, weight=1)

        self.home_frame_image = customtkinter.CTkLabel(self.home_frame, text="", image=self.logo_image)
        self.home_frame_image.grid(row=0, column=0, padx=20, pady=10)

        #self.home_text = customtkinter.CTkTextbox(self.home_frame, width=50)
        #self.home_text.grid(row=0, column=0, sticky="nsew")

        #self.home_text.insert("0.0", "Bienvenido a su interfaz de firma digital")

        #---------------------------------------------------------------------------------------------------------
        #---------------------------------------------------------------------------------------------------------

        self.second_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.second_frame.grid_columnconfigure(0, weight=1)
        self.second_frame_image = customtkinter.CTkLabel(self.second_frame, text="", image=self.logo_image) 
        self.second_frame_image.grid(row=0, column=0, padx=20, pady=10)
        
        self.second_frame_llave= tk.StringVar()
        self.second_frame_file_path = tk.StringVar()
        self.second_frame_private_key_path = tk.StringVar()
        self.second_frame_public_key_path = tk.StringVar()
        self.second_frame_file_ver_path = tk.StringVar()
        self.second_frame_signature = None   

        llave_label = customtkinter.CTkLabel(self.second_frame, text="Genera tu par de llaves")
        llave_label.grid()
        self.llave_entry = customtkinter.CTkEntry(self.second_frame, textvariable=self.second_frame_llave)
        self.llave_entry.grid()
        llave_button = customtkinter.CTkButton(self.second_frame, text="Genera tu llave:", command=self.key_gen)
        llave_button.grid()

        file_label = customtkinter.CTkLabel(self.second_frame, text="PDF File:")
        file_label.grid()
        self.file_entry = customtkinter.CTkEntry(self.second_frame, textvariable=self.second_frame_file_path)
        self.file_entry.grid()
        file_button = customtkinter.CTkButton(self.second_frame, text="Browse", command=self.browse_file)
        file_button.grid()

        private_key_label = customtkinter.CTkLabel(self.second_frame, text="Private Key:")
        private_key_label.grid()
        self.private_key_entry = customtkinter.CTkEntry(self.second_frame, textvariable=self.second_frame_private_key_path)
        self.private_key_entry.grid()
        private_key_button = customtkinter.CTkButton(self.second_frame, text="Browse", command=self.browse_private_key)
        private_key_button.grid()

        public_key_label = customtkinter.CTkLabel(self.second_frame, text="Public Key:")
        public_key_label.grid()
        self.public_key_entry = customtkinter.CTkEntry(self.second_frame, textvariable=self.second_frame_public_key_path)
        self.public_key_entry.grid()
        public_key_button = customtkinter.CTkButton(self.second_frame, text="Browse", command=self.browse_public_key)
        public_key_button.grid()

        sign_button = customtkinter.CTkButton(self.second_frame, text="Sign", command=self.sign)
        sign_button.grid()

        #file_ver_label = tk.Label(root, text="Files to verify:")
        #file_ver_label.pack()
        #self.file_ver_entry = tk.Entry(root, textvariable=self.file_ver_path)
        #self.file_ver_entry.pack()
        #file_ver_button = tk.Button(root, text="Browse", command=self.browse_file_verify)
        #file_ver_button.pack()

        verify_button = customtkinter.CTkButton(self.second_frame, text="Verify", command=self.verify)
        verify_button.grid()


        #---------------------------------------------------------------------------------------------------------
        #---------------------------------------------------------------------------------------------------------

        self.third_frame = customtkinter.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.third_frame.grid_columnconfigure(0, weight=1)
        self.third_frame_image = customtkinter.CTkLabel(self.second_frame, text="", image=self.logo_image) 
        self.third_frame_image.grid(row=0, column=0, padx=20, pady=10)

        #self.pais = tk.StringVar()
        self.state = tk.StringVar()
        self.local = tk.StringVar()
        self.org = tk.StringVar()
        self.orgunit = tk.StringVar()
        self.common_name = tk.StringVar()
        self.email = tk.StringVar()
        self.client_ca = tk.StringVar()
        self.third_frame_file_path = tk.StringVar()
        self.x_coordinate = tk.IntVar()
        self.y_coordinate = tk.IntVar()
        self.signature_id = tk.StringVar()
        self.pages = None
        self.signature_img = tk.StringVar()
        self.container = tk.StringVar()
        self.cert = tk.StringVar()
        self.private_key_c = tk.StringVar()
        #self.third_frame_private_key_path = tk.StringVar()
        #self.third_frame_public_key_path = tk.StringVar()
        #self.third_frame_file_ver_path = tk.StringVar()
        #self.third_frame_signature = None 

        cert_label = customtkinter.CTkLabel(self.third_frame, text="Genera tu certificado, llenando los campos")
        cert_label.grid()

        #cert_label_pais = customtkinter.CTkLabel(self.third_frame, text="Pais de origen: ")
        #cert_label_pais.grid()
        #self.pais_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.pais)
        #self.pais_entry.grid()

        cert_label_state = customtkinter.CTkLabel(self.third_frame, text="Estado o provincia: ")
        cert_label_state.grid()
        self.state_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.state)
        self.state_entry.grid()


        cert_local_label = customtkinter.CTkLabel(self.third_frame, text="Nombre de localidad: (Ciudad)")
        cert_local_label.grid()
        self.local_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.local)
        self.local_entry.grid()

        cert_org_label = customtkinter.CTkLabel(self.third_frame, text="Nombre de la organizacion: ")
        cert_org_label.grid()
        self.org_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.org)
        self.org_entry.grid()

        cert_org_unit_label = customtkinter.CTkLabel(self.third_frame, text="Nombre de la unidad emisora: ")
        cert_org_unit_label.grid()
        self.orgunit_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.orgunit)
        self.orgunit_entry.grid()

        cert_common_name_label = customtkinter.CTkLabel(self.third_frame, text="Nombre del servidor del administrador: ")
        cert_common_name_label.grid()
        self.common_name_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.common_name)
        self.common_name_entry.grid()

        cert_email_label = customtkinter.CTkLabel(self.third_frame, text="Dirrecion de correo electronico: ")
        cert_email_label.grid()
        self.email_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.email)
        self.email_entry.grid()

        gen_cert_button = customtkinter.CTkButton(self.third_frame, text="Generar certificado", command=self.main)
        gen_cert_button.grid()

        client_ca_label = customtkinter.CTkLabel(self.third_frame, text="Certificado del cliente CN: ")
        client_ca_label.grid()
        self.client_ca_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.client_ca)
        self.client_ca_entry.grid()



        file_label = customtkinter.CTkLabel(self.third_frame, text="PDF File:")
        file_label.grid()
        self.file_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.third_frame_file_path)
        self.file_entry.grid()
        file_button = customtkinter.CTkButton(self.third_frame, text="Browse", command=self.browse_file)
        file_button.grid()

        cert_label_sel = customtkinter.CTkLabel(self.third_frame, text="Archivo certificado .pem: ")
        cert_label_sel.grid()
        self.cert_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.cert)
        self.cert_entry.grid()
        cert_button = customtkinter.CTkButton(self.third_frame, text="Browse", command=self.browse_file_cert)
        cert_button.grid()


        private_key_c_label = customtkinter.CTkLabel(self.third_frame, text="Private Key:")
        private_key_c_label.grid()
        self.private_key_c_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.private_key_c)
        self.private_key_c_entry.grid()
        private_key_c_button = customtkinter.CTkButton(self.third_frame, text="Browse", command=self.browse_private_key)
        private_key_c_button.grid()

        sign_pdf_cert_button = customtkinter.CTkButton(self.third_frame, text="Firmar PDF", command=self.sign_pdf_cr)
        sign_pdf_cert_button.grid()

        signature_label = customtkinter.CTkLabel(self.third_frame, text="Firma: ")
        signature_label.grid()
        self.signature_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.signature_img)
        self.signature_entry.grid()
        signature_button = customtkinter.CTkButton(self.third_frame, text="Browse", command=self.browse_file_signature)
        signature_button.grid()

        pfx_label = customtkinter.CTkLabel(self.third_frame, text="Archivo pfx: ")
        pfx_label.grid()
        self.pfx_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.container)
        self.pfx_entry.grid()
        pfx_button = customtkinter.CTkButton(self.third_frame, text="Browse", command=self.browse_file_pfx)
        pfx_button.grid()

        

        x_coordinate_label = customtkinter.CTkLabel(self.third_frame, text="Posicion en X del documento: ")
        x_coordinate_label.grid()
        self.x_coordinate_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.x_coordinate)
        self.x_coordinate_entry.grid()

        y_coordinate_label = customtkinter.CTkLabel(self.third_frame, text="Posicion en Y del documento: ")
        y_coordinate_label.grid()
        self.y_coordinate_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.y_coordinate)
        self.y_coordinate_entry.grid()

        signature_id_label = customtkinter.CTkLabel(self.third_frame, text="ID firma; ")
        signature_id_label.grid()
        self.signature_id_entry = customtkinter.CTkEntry(self.third_frame, textvariable=self.signature_id)
        self.signature_id_entry.grid()

        

        sign_pdf_button = customtkinter.CTkButton(self.third_frame, text="Firmar PDF", command=self.sign_pdf)
        sign_pdf_button.grid()
        #---------------------------------------------------------------------------------------------------------
        #Default window
        self.select_frame_by_name("home")


    def select_frame_by_name(self,name):
        self.home_button.configure(fg_color=("gray75", "gray25") if name == "home" else "transparent")
        self.frame_2_button.configure(fg_color=("gray75", "gray25") if name == "frame_2" else "transparent")
        self.frame_3_button.configure(fg_color=("gray75", "gray25") if name == "frame_3" else "transparent")

        if name == "home":
            self.home_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.home_frame.grid_forget()
        if name == "frame_2":
            self.second_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.second_frame.grid_forget()
        if name == "frame_3":
            self.third_frame.grid(row=0, column=1, sticky="nsew")
        else:
            self.third_frame.grid_forget()

    def home_button_event(self):
        self.select_frame_by_name("home")

    def frame_2_button_event(self):
        self.select_frame_by_name("frame_2")
    
    def frame_3_button_event(self):
        self.select_frame_by_name("frame_3")

    def key_gen(self):
        llave = self.llave_entry.get()
        zip_name = "Keys.zip" #input("Que tipo de llave desea: ")
        if llave == "RSA":
            key_rsa = RSA.generate(2048)
            key_path_dir = "Keys"
            os.makedirs(key_path_dir, exist_ok=True)
            public_key_rsa = os.path.join(key_path_dir, "public_key.pem")
            with open(public_key_rsa, "wb") as public_key_file:
                public_key_file.write(key_rsa.public_key().export_key())
            private_key_rsa = os.path.join(key_path_dir, "private_key.pem")
            with open(private_key_rsa, "wb") as private_key_file:
                private_key_file.write(key_rsa.export_key())

            with zipfile.ZipFile(zip_name, "w") as zip_file:
                zip_file.write(private_key_rsa, "Private_key.pem")
                zip_file.write(public_key_rsa, "Public_key.pem")
            
            os.remove(private_key_rsa)
            os.remove(public_key_rsa)

            os.rmdir(key_path_dir)

            messagebox.showinfo("Llave publica privada y publica generada, puedes buscarla en tu directorio")

  


    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=(("PDF files", "*.pdf"), ("All files", "*.*")))
        self.second_frame_file_path.set(file_path)
        self.third_frame_file_path.set(file_path)

    def browse_private_key(self):
        private_key_path = filedialog.askopenfilename(filetypes=(("Private Key files", "*.pem"), ("All files", "*.*")))
        self.second_frame_private_key_path.set(private_key_path)
        self.private_key_c.set(private_key_path)

    def browse_public_key(self):
        public_key_path = filedialog.askopenfilename(filetypes=(("Public Key files", "*.pem"), ("All files", "*.*")))
        self.second_frame_public_key_path.set(public_key_path)
    
    def browse_file_verify(self):
        file_path_ver = filedialog.askopenfilename(filetypes=(("verify files", "*.pem"), ("All files", "*.*")))
        self.second_frame_file_ver_path.set(file_path_ver)

    def browse_file_signature(self):
        file_path_sign = filedialog.askopenfile(filetypes=(("JPG files", "*.jpg"), ("All files", "*.*")))
        self.signature_img.set(file_path_sign)

    def browse_file_pfx(self):
        file_path_pfx = filedialog.askopenfile(filetypes=(("PFX files", "*.pfx"), ("All files", "*.*")))
        self.container.set(file_path_pfx)
    
    def browse_file_cert(self):
        file_path_cert = filedialog.askopenfilename(filetypes=(("verify files", "*.pem"), ("All files", "*.*")))
        self.cert.set(file_path_cert)


    

    def sign(self):
        file_path = self.second_frame_file_path.get()
        private_key_path = self.second_frame_private_key_path.get()

        if not file_path or not private_key_path:
            messagebox.showerror("Error", "Please provide all file paths.")
            return

        try:
            with open(file_path, 'rb') as file:
                pdf = file.read()
                hash_obj = SHA256.new(pdf)

                private_key_pem = RSA.import_key(open(private_key_path, 'rb').read())
                self.signature = Signature_pkcs1_v1_5.new(private_key_pem).sign(hash_obj)

                signature_file_64 = b64encode(self.signature)
                firma = open("Firma.txt", "wb")
                firma.write(signature_file_64)



                signature_file = open("Signature_file.pem", "wb")
                signature_file.write(self.signature)

            messagebox.showinfo("Success", "PDF signed successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            #return signature_file_64

    
    def verify(self):
        file_path = self.second_frame_file_path.get()
        public_key_path = self.second_frame_public_key_path.get()  

        if not public_key_path or not file_path:
            messagebox.showerror("Error", "Please provide all file paths.")
            return

        try:
            with open(file_path, 'rb') as file:
                pdf = file.read()
                
                public_key_pem = RSA.import_key(open(public_key_path, 'rb').read())
                hash_obj = SHA256.new(pdf)
                verifier = Signature_pkcs1_v1_5.new(public_key_pem).verify(hash_obj, signature=self.signature)

                if verifier:
                    messagebox.showinfo("Success", "Signature is valid.")
                else:
                   messagebox.showwarning("Warning", "Signature is not valid.")

        except Exception as e:
            messagebox.showerror("Error", str(e))


    def create_CA(self,root_ca_path, key_path):
        ''' Create CA and Key'''
    
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 4096)


        ca_cert = crypto.X509()
        ca_cert.set_version(2)
        ca_cert.set_serial_number(random.randint(50000000, 100000000))


        ca_subj = ca_cert.get_subject()
        #ca_subj.countryName = self.pais_entry.get()
        ca_subj.stateOrProvinceName = self.state_entry.get()   #input("Estado o nombre de ciudad (nombre completo) []: ")
        ca_subj.localityName = self.local_entry.get()  #input("Nombre de la localidad (eg, city) [Default City]: ")
        ca_subj.organizationName = self.org_entry.get() #input("Nombre de la organizacion (ej, company) [Default Company Ltd]: ")
        ca_subj.organizationalUnitName = self.orgunit_entry.get() #input("Nombre de la unidad organizacional (ej, seccion) []: ")
        ca_subj.commonName = self.common_name_entry.get() #input("Nombre usual (ej, su nombre o del servidor del administrador) []: ")
        ca_subj.emailAddress = self.email_entry.get() #input("Correo electronico []: ")
    
        ca_cert.set_issuer(ca_subj)
        ca_cert.set_pubkey(ca_key)

        ca_cert.add_extensions([
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
        ])

        ca_cert.add_extensions([
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always,issuer", issuer=ca_cert),
        ])

        ca_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        #crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyCertSign, cRLSign"),
        ])


        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(10*365*24*60*60)

        ca_cert.sign(ca_key, 'sha256')

        # Save certificate
        with open(root_ca_path, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert).decode("utf-8"))

        # Save private key
        with open(key_path, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key).decode("utf-8"))


        messagebox.showinfo("Success", "CA Certificate and key created successfully!")
        
    
        
    def load_CA(self, root_ca_path, key_path):
        ''' Load CA and Key'''

        with open(root_ca_path, "r") as f:
            ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
        with open(key_path, "r") as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
        return ca_cert, ca_key


    def CA_varification(self, ca_cert):  
        ''' Varify the CA certificate '''

        ca_expiry = datetime.strptime(str(ca_cert.get_notAfter(), 'utf-8'),"%Y%m%d%H%M%SZ")
        now = datetime.now()
        validity = (ca_expiry - now).days
        messagebox.showinfo("CA Certificate valid for {} days".format(validity))
    
            
    def create_cert(self, ca_cert, ca_subj, ca_key, client_cn):
        ''' Create Client certificate '''
    
        client_key = crypto.PKey()
        client_key.generate_key(crypto.TYPE_RSA, 4096)

        client_cert = crypto.X509()
        client_cert.set_version(2)
        client_cert.set_serial_number(random.randint(50000000, 100000000))

        client_subj = client_cert.get_subject()
        client_subj.commonName = client_cn
    
        client_cert.set_issuer(ca_subj)
        client_cert.set_pubkey(client_key)

        client_cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        ])

        client_cert.add_extensions([
            crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid", issuer=ca_cert),
            #crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth"),
            crypto.X509Extension(b"keyUsage", True, b"digitalSignature, keyEncipherment"),
        ])

        client_cert.add_extensions([
            crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=client_cert),
        ])
    
        client_cert.gmtime_adj_notBefore(0)
        client_cert.gmtime_adj_notAfter(365*24*60*60)

        client_cert.sign(ca_key, 'sha256')


        with open(client_cn + ".crt", "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, client_cert).decode("utf-8"))


        with open(client_cn + ".key", "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, client_key).decode("utf-8"))

    def client_varification():
        pass
    

        
    def main(self):
    
        '''Create self signed certificates'''

        key_path = "CA/ca.key"
        root_ca_path = "CA/ca.crt"
    
    
        if not os.path.exists('CA'):
            print ("Creating CA driectory")
            os.makedirs('CA')
        
        if not os.path.exists(root_ca_path):
            print ("Creating CA Certificate, Please provide the values")
            self.create_CA(root_ca_path, key_path)
            print ("Created CA Certificate")
            ca_cert, ca_key = self.load_CA(root_ca_path, key_path)
            self.CA_varification(ca_cert)
        else:
            print ("CA certificate has been found as {}".format(root_ca_path))
            ca_cert, ca_key = self.load_CA(root_ca_path, key_path)
            self.CA_varification(ca_cert)
    

        while True:    
            client_cn = self.client_ca_entry.get()
            if client_cn != '':
                break
            else:
                messagebox.showinfo("Please provide a valid CN for client certificate")
            
        subject = ca_cert.get_subject()
        self.create_cert(ca_cert, subject, ca_key, client_cn)
        p12 = crypto.PKCS12()
        p12.set_privatekey(ca_key)
        p12.set_certificate(ca_cert)
        open("PKCS12.pfx", 'wb').write(p12.export())

    
    
    def sign_pdf_cr(self):
        cert_file = self.cert.get()
        private_key_file = self.private_key_c.get()
        with open(cert_file, "rb") as f:
            cert_data = f.read()
        with open(private_key_file, "rb") as f:
            private_key_data = f.read()
        
        cert_d = x509.load_der_x509_certificate(cert_data, default_backend())

        public_key = cert_d.public_key()
        private_key = serialization.load_pem_private_key(private_key_data, password=None, backend=default_backend())

        document = ""
        hash_value = hashes.Hash(hashes.SHA256(), default_backend())
        hash_value.update(document)
        hash_digest = hash_value.finalize()

        signature = private_key.sign(hash_digest, padding.PKCS1v15(), hashes.SHA256())

        with open("Firma.pem", "wb") as f:
            f.write(signature)

        messagebox.showinfo("Documento firmado, revise su directorio")

    def sign_pdf(self):
        input_file = self.third_frame_file_path.get()
        output_file = None
        if not output_file:
            output_file = (os.path.splitext(input_file)[0]) + "_signed.pdf"
        
        PDFNet.PDFNet_Initialize()
        #pages = 
        document = PDFNet.PDFDoc(input_file)
        sigField = PDFNet.SignatureWidget.Create(document, PDFNet.Rect(int(self.x_coordinate_entry.get()), int(self.y__coordinate_entry.get()), 
                                                         int(self.x_coordinate_entry.get())+100, int(self.y__coordinate_entry.get())+50), self.signature_id_entry.get())
        for page in range(1, (document.GetPageCount()+1)):
            if self.pages:
                if str(page) not in self.pages:
                    continue
            pg = document.GetPage(page)
            pg.AnnotPushBack(sigField)
        
        sign_filename = self.signature_id.get() #os.path.dirname(os.path.abspath(__file__)) + ""
        pk_filename = self.container.get()#os.path.dirname(os.path.abspath(__file__)) + ""

        approval_field = document.GetField(self.signature_id_entry.get())
        approval_siganture_digsig_field = PDFNet.DigitalSignatureField(approval_field)

        img = Image.Create(document.GetSDFDoc(), sign_filename)
        found_approval_siganture_widget = PDFNet.SignatureWidget(approval_field.GetSDFObj())
        found_approval_siganture_widget.CreateSignatureAppearance(img)

        approval_siganture_digsig_field.SignOnNextSave(pk_filename, '')
        document.Save(output_file, PDFNet.SDFDoc.e_incremental)



if __name__ == '__main__':
    app = DigitalSignatureGUI()
    app.mainloop()