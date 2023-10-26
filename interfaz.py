import json
from tkinter import *
import creador
import kdf

def register_user():
    username_info = username.get()
    password_info = password.get()
    # simmetric_info = new_simmetric.get()

    """
    file = open(username_info+".txt", "w")
    file.write(username_info+"\n")
    file.write(password_info)
    file.close()
    """
    key, salt = kdf.derivar(password_info)

    creador.registrar(username_info, str(key), str(salt))

    new_username.delete(0, END)
    new_password.delete(0, END)

    Label(screen_registro, text="Éxito al registrarse", fg="green", font=("Calibri", 11)).pack()

def login_user():
    # username_info = actual_username.get()
    # password_info = actual_password.get()
    # data = StringVar()

    # key, salt = kdf.derivar(password_info)

    # with open("json/registro.json", 'r') as archivo:
    #     file = json.load(archivo)

    # for entry in file:
    #     if entry["Username"] == username_info:
    #         print(entry["salt"])
    #         print(str(salt))
    #     if entry["Username"] == username_info and entry["salt"] == str(salt):
    #         # screen_archivo = Toplevel(screen)
    #         # screen_archivo.title("Añadir archivo")
    #         # screen_archivo.geometry("300x250")
    #         screen_login.geometry("300x300")
    #         Label(screen_login, text="")
    #         Label(screen_login, text="Introduzca el archivo encriptado").pack()
    #         Entry(screen_login, textvariable=data).pack()
    #         Button(screen_login, text="Enviar", width=10, height=1).pack()

    password_info = actual_password.get()
    key, salt = kdf.derivar(password_info)
    
    if kdf.verificacion(salt):
        screen_login.geometry("300x300")
        Label(screen_login, text="")
        Label(screen_login, text="Introduzca el archivo encriptado").pack()
        Entry(screen_login, textvariable=data).pack()
        Button(screen_login, text="Enviar", width=10, height=1).pack()


def arhivo():
    ...

def register():
    global username
    global password
    global new_username
    global new_password
    global new_simmetric
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
    # Label(screen_registro, text="Contraseña simétrica * ").pack()
    # new_simmetric = Entry(screen_registro, textvariable=password)
    # new_simmetric.pack()
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