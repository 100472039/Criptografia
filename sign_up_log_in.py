
from kdf import *
from creador import *

def sign_up():
    print("SIGN UP")
    user=input("Your username: ")
    password = input("Introduzca su contraseña: ")
    password = bytes(password, encoding='utf-8')
    key, salt = derivar(password)
    add(user, str(salt), str(key), str(password))


def log_in():
    print("LOG IN")
    user=input("Your username: ")
    newpassword=input("Enter password: ")
    key = getkey(user)
    salt = getsalt(user)
    if verificar(key, salt, newpassword):
        print("contraseña correcta")
    else:
        print("contraseña incorrecta")

