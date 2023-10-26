
from kdf import *
from creador import *

def sign_up():
    print("SIGN UP")
    user=input("Introduzca su user: ")
    password = input("Introduzca su contraseña: ")
    key, salt = derivar(password)
    registrar(user, str(key), str(salt))


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
            key=datos_existentes[i]["key"]
            salt=datos_existentes[i]["salt"]

            if verificar(key, salt, newpassword):
                print("contraseña correcta")
            else:
                print("contraseña incorrecta")



    # key = getkey(user)
    # salt = getsalt(user)
    # if verificar(key, salt, newpassword):
    #     print("contraseña correcta")
    # else:
    #     print("contraseña incorrecta")

log_in()