from tkinter import *
from tkinter.filedialog import askopenfilename
from creador import *
from kdf import *
from asimetrico import *

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend


def register_user():
    username_info = username.get()
    password_info = password.get()
    # simmetric_info = new_simmetric.get()


    key, salt = derivar(password_info)
    user_privada, user_publica = generar_asimetrico()
    user_simetrica = generar_simetrico()
    añadir_registro(username_info, key, salt)
    añadir_claves_usuario(username_info, user_privada, user_publica, user_simetrica)

    new_username.delete(0, END)
    new_password.delete(0, END)

    Label(screen_registro, text="Éxito al registrarse", fg="green", font=("Calibri", 11)).pack()

def login_user():
    global entry_data_name
    global entry_data
    global screen_data
    user = actual_username.get()
    newpassword = actual_password.get()

    data_name = StringVar()
    data = StringVar()

    if buscar(user, newpassword):

        session_key = session_keys_generator(user)
        # print("session_key:\n"+str(session_key))
        session_key_cifrada = cifrar_con_publica(user, session_key)
        # print("session_key_cifrada:\n"+str(session_key_cifrada))
        session_key_descifrada = descifrar_con_privada(user, session_key_cifrada)
        # print("session_key_descifrada:\n"+str(session_key_descifrada))
        añadir_user_session_keys(user, str(session_key_cifrada), session_key_descifrada.decode())
        #simetrico = descifrar_con_privada(user, session_key)
        #añadir_simetrico(user, session_key, simetrico)
        
        screen_login.destroy()
        screen_data = Toplevel(screen)
        screen_data.geometry("300x300")
        screen_data.title("Hola, "+str(user))

        Label(screen_data, text="Añadir un archivo nuevo").pack()
        Label(screen_data, text="").pack()
        Label(screen_data, text="Nombre del archivo").pack()
        entry_data_name = Entry(screen_data, textvariable=data_name)
        entry_data_name.pack()
        Label(screen_data, text="Introduzca el archivo de audio").pack()
        # entry_data = Entry(screen_data, textvariable=data)
        # entry_data.pack()
        entry_data = Button(screen_data, text="Browse Folder", font =("Roboto", 14),command=browse)
        entry_data.pack()
        Label(screen_data, text="").pack()
        Button(screen_data, text="Enviar", width=14, height=1, command=añadir_archivo).pack()
        Button(screen_data, text="Recuperar archivo", width=14, height=1, command=ventana_recuperar).pack()
        Button(screen_data, text="Cerrar sesión", width=14, height=1, command=cerrar_sesion).pack()

    else:
        Label(screen_login, text="Combinación incorrecta", fg="red", font=("Calibri", 11)).pack()
    
def añadir_archivo():
    user = actual_username.get()
    data_name = entry_data_name.get()
    # data = entry_data.get()
    data = original_audio

    # El mensaje es encriptado con la pública del usuario y la session key. Data_encrypt es una tupla que contiene el cifrado, el tag y la firma
    data_encrypt, firma, tag = encriptar_mensaje(user, data)
    # Los datos se desencriptan con la session key antes de guardarlos

    # print("data_encrypt:\n"+str(data_encrypt[0])+"\n"+str(data_encrypt[1])+"\n"+str(firma))
    # El usuario envía el mensaje y el programa lo desencripta con la session_key
    simetrica = buscar_session_key(user, True).encode()
    data_simetrica = descifrado_simetrico(simetrica, data_encrypt[0], data_encrypt[1])
    comprobar_firma(user, firma, data_simetrica)
    añadir_datos(user, data_name, data_simetrica.hex(), tag.hex())


    entry_data_name.delete(0, END)
    # entry_data.delete(0, END)
    print("Tipo de dato", type(data_simetrica), type(data_simetrica.hex()))

    Label(screen_data, text="Datos guardados", fg="green", font=("Calibri", 11)).pack()

def browse():
    global original_audio

    read_path = askopenfilename(initialdir="/home/alberto/",
        title="Select File", filetypes=(("Audio files", "*.mp3*"), ("All Files","*.*")))
    # screen_data.configure(text="File Opened: "+read_path)

    with open(read_path, 'rb') as file:
        original_audio=file.read()
    
    print("Audio encriptado y guardado")
    original_audio = original_audio.hex()

def ventana_recuperar():
    user = actual_username.get()
    global return_data
    data_name = StringVar()

    screen_data.destroy()
    screen_data_recover = Toplevel(screen)
    screen_data_recover.geometry("300x250")
    screen_data_recover.title("Hola, "+str(user))

    Label(screen_data_recover, text="Recuperar un archivo").pack()
    Label(screen_data_recover, text="").pack()
    Label(screen_data_recover, text="Nombre del archivo").pack()
    return_data = Entry(screen_data_recover, textvariable=data_name)
    return_data.pack()
    Label(screen_data_recover, text="").pack()
    Button(screen_data_recover, text="Enviar", width=10, height=1, command=recuperar_archivo).pack()

def cerrar_sesion():
    user = actual_username.get()
    remove_session_key(user)
    screen_data.destroy()

def recuperar_archivo():
    user = actual_username.get()
    data_name = return_data.get()
    # print("data_name:\n"+str(data_name))
    tag = bytes.fromhex(buscar_tag(user, data_name))
    data_simetrica = bytes.fromhex(buscar_dato(user, data_name))
    # print("data:\n"+str(data_publica))
    session_key = buscar_session_key(user, True).encode()
    # print("simetrica:\n"+str(simetrica))
    # print("simetrica_encode:\n"+str(simetrica_encode))
    #El mensaje se firma con la privada del programa
    firma = firmar("programa", data_simetrica)
    #El mensaje se encripta antes de ser enviado con la session_key
    data_encrypt = cifrado_simetrico(session_key, data_simetrica)
    # print("data_encrypt:\n"+str(data_encrypt[0]))
    #Una vez llega, el mensaje es desencriptado con la session_key y la simétrica del usuario
    session_key = buscar_session_key(user, False).encode()
    data_devuelta = descifrado_simetrico(session_key, data_encrypt[0], data_encrypt[1])
    comprobar_firma("programa", firma, data_devuelta)
    # print("data_devuelta:\n"+str(data_devuelta))
    simetrica = buscar_simetrica(user).encode()
    data_encode = descifrado_simetrico(simetrica, data_devuelta, tag)
    # print("data_encode:\n"+str(data_encode))
    data_final = data_encode.decode()
    print("tipo de data_final", type(data_final))
    print("data_final:\n"+str(data_final))
    añadir_datos_recuperados(user, data_name, data_final)


def register():
    global username
    global password
    global new_username
    global new_password
    global screen_registro
    screen_registro = Toplevel(screen)
    screen_registro.title("Registro")
    screen_registro.geometry("300x250")

    username = StringVar()
    password = StringVar()

    Label(screen_registro, text="Introduzca los datos").pack()
    Label(screen_registro, text="").pack()
    Label(screen_registro, text="Usuario * ").pack()
    new_username = Entry(screen_registro, textvariable=username)
    new_username.pack()
    Label(screen_registro, text="Contraseña * ").pack()
    new_password = Entry(screen_registro, textvariable=password)
    new_password.pack()
    Button(screen_registro, text="Registrarse", width=10, height=1, command=register_user).pack()


def login():
    global screen_login
    global actual_username
    global actual_password
    screen_login = Toplevel(screen)
    screen_login.title("Login")
    screen_login.geometry("300x250")

    actual_username = StringVar()
    actual_password = StringVar()

    Label(screen_login, text="Introduzca los datos").pack()
    Label(screen_login, text="").pack()
    Label(screen_login, text="Usuario * ").pack()
    username_entry = Entry(screen_login, textvariable=actual_username)
    username_entry.pack()
    Label(screen_login, text="Contraseña *").pack()
    password_entry = Entry(screen_login, textvariable=actual_password)
    password_entry.pack()
    Label(screen_login, text="").pack()
    Button(screen_login, text="Entrar", width=10, height=1, command=login_user).pack()


def main_screen():
    programa_privada, programa_publica = generar_asimetrico()
    añadir_claves_programa("programa", programa_privada, programa_publica)

    global screen
    screen = Tk()
    screen.geometry("300x250")
    screen.title("Inicio")

    button_height = 2
    button_width = 30

    Label(text = "Login/Registro", bg="grey", width="300", height="2", font=("Calibri", 13)).pack()
    Label(text="").pack()
    Button(text="Login", height=button_height, width=button_width, command=login).pack()
    Label(text="").pack()
    Button(text="Register", height=button_height, width=button_width, command=register).pack()


    screen.mainloop()

main_screen()