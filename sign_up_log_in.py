
from kdf import *
from creador import *
from asimetrico import *


from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend

def sign_up():
    print("SIGN UP")
    user=input("Introduzca su user: ")
    password = input("Introduzca su contraseña: ")
    key, salt = derivar(password)
    registrar(user, key, salt)


def log_in():
    print("LOG IN")
    user=input("Your username: ")
    newpassword=input("Enter password: ")

    path = "json/registro.json"
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    try:
        with open(path, "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        print("No hay datos en el registro")
    

    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"]==user:
            print("User es ", user)
            key=bytes.fromhex(datos_existentes[i]["key"])
            salt=bytes.fromhex(datos_existentes[i]["salt"])

            if verificar(key, salt, newpassword):
                print("contraseña correcta")
                found=True
                
            else:
                print("contraseña incorrecta")
                found=False
            break
        else:
            found=False

    if found:
        return True
    else:
        return False
        






    # key = getkey(user)
    # salt = getsalt(user)
    # if verificar(key, salt, newpassword):
    #     print("contraseña correcta")
    # else:
    #     print("contraseña incorrecta")



