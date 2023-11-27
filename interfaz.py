import json
from tkinter import *
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
    añadir_registro(username_info, key, salt)
    añadir_asimetrico(username_info, user_privada, user_publica)

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


        screen_login.destroy()
        screen_data = Toplevel(screen)
        screen_data.geometry("300x250")
        screen_data.title("Hola, "+str(user))

        Label(screen_data, text="").pack()
        Label(screen_data, text="Nombre del archivo").pack()
        entry_data_name = Entry(screen_data, textvariable=data_name)
        entry_data_name.pack()
        Label(screen_data, text="Introduzca el archivo de audio").pack()
        entry_data = Entry(screen_data, textvariable=data)
        entry_data.pack()
        Label(screen_data, text="").pack()
        Button(screen_data, text="Enviar", width=10, height=1, command=archivo).pack()

        #session_key = session_keys_generator(user)
    else:
        Label(screen_login, text="Combinación incorrecta", fg="red", font=("Calibri", 11)).pack()
    
def archivo():
    user = actual_username.get()
    data_name = entry_data_name.get()
    data = entry_data.get()

    data_encypt = cifrar_con_publica(user, data)
    añadir_datos(user, data_name, data_encypt)

    entry_data_name.delete(0, END)
    entry_data.delete(0, END)

    Label(screen_data, text="Datos guardados", fg="green", font=("Calibri", 11)).pack()

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
    Button(screen_login, text="Entrar", width=10, height=1, command=login_user).pack()


def main_screen():
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