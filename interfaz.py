import json
from tkinter import *
from creador import *
from kdf import *
import kdf

def register_user():
    username_info = username.get()
    password_info = password.get()
    # simmetric_info = new_simmetric.get()

    key, salt = derivar(password_info)
    registrar(username_info, key, salt)

    new_username.delete(0, END)
    new_password.delete(0, END)

    Label(screen_registro, text="Éxito al registrarse", fg="green", font=("Calibri", 11)).pack()

def login_user():

    user = actual_username.get()
    newpassword = actual_password.get()

    data = StringVar()

    if buscar(user, newpassword):
        screen_login.destroy()
        screen_data = Toplevel(screen)
        screen_data.geometry("300x250")
        screen_data.title("Hola, "+str(user))
        Label(screen_data, text="").pack()
        Label(screen_data, text="Introduzca el archivo de audio").pack()
        Label(screen_data, text="").pack()
        Label(screen_data, text="").pack()
        Entry(screen_data, textvariable=data).pack()
        Label(screen_data, text="").pack()
        Label(screen_data, text="").pack()
        Button(screen_data, text="Enviar", width=10, height=1).pack()
    else:
        Label(screen_login, text="Combinación incorrecta", fg="red", font=("Calibri", 11)).pack()
    
    

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