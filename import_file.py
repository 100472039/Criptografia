
import tkinter as tk
from tkinter.filedialog import askopenfilename
from asimetrico import *

simetrica = Fernet.generate_key()
fernet = Fernet(simetrica)

def browse(fernet):
    read_path = askopenfilename(initialdir="/",
        title="Select File", filetypes=(("Audio files", "*.mp3*"), ("All Files","*.*")))
    file_explorer.configure(text="File Opened: "+read_path)

    with open(read_path, 'rb') as file:
        original_audio=file.read()

    
    # with open("C:/Users/agued/Desktop/Cripto/Criptografia/documentos/audio_sin.txt", 'wb') as file:
    #     file.write(original_audio)
    # privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # publica = privada.public_key()
    # cifrado=cifrar_con_publica(publica, original_audio)
    
    cifrado = fernet.encrypt(original_audio)

    save_path="C:/home/alberto/Documentos/Criptografia/Criptografia/documentos/"+ "prueba_encriptada" + ".mp3"
    with open(save_path, 'wb') as enc_file:
        enc_file.write(cifrado)
    
    print("Audio encriptado y guardado")

def recuperar(nombre, fernet):
    read_path= "C:/home/alberto/Documentos/Criptografia/Criptografia/documentos/"+ "prueba_encriptada" +".mp3"
    with open(read_path, 'rb') as file:
        audio_c_after=file.read()
    

    audio_after = fernet.decrypt(audio_c_after)
    save_path="C:/Users/agued/Desktop/Cripto/Criptografia/documentos/" + nombre + ".mp3"
    with open(save_path, 'wb') as file:
        file.write(audio_after)

    print("audio desencriptado y guardado con éxito")

     
nombre="mi_archivo"  


root = tk.Tk()
root.title("File Explorer")
root.geometry("750x350")

root.config(background="black")

file_explorer = tk.Label(root, text="Explore files",
   font=("Verdana", 14, "bold"),
   width=100,
   height=4, fg="white", bg="gray")

button=tk.Button(root, text="Browse Folder", font =("Roboto", 14),
   command=browse(fernet))
file_explorer.pack()
button.pack(pady=10)

recuperar=tk.Button(root, text="Recuperar", font =("Roboto", 14),
   command=recuperar(nombre, fernet))
file_explorer.pack()
recuperar.pack(pady=10)

root.mainloop()