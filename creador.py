import json
from kdf import *

path = "json/datos.json"

def add(path, entradas, valores):
    #comprobar que los valores de entrada son valores
    if len(entradas) != len(valores):
        print("Valores de entrada inválidos")
        return -1
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    try:
        with open(path, "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        datos_existentes = []
    
    # Añadir nuevos datos al diccionario existente
    nuevos_datos = {
    }

    for i in range(len(valores)):
        nuevos_datos[entradas[i]] = valores[i]

    datos_existentes.append(nuevos_datos)

    # Escribir el diccionario actualizado de vuelta al archivo JSON
    with open(path, "w") as archivo_json:
        json.dump(datos_existentes, archivo_json, indent=4)

    print("Nuevos datos añadidos al archivo JSON correctamente.")
 
def añadir_registro(usuario, key, salt):
    path = "json/registro.json"
    add(path, ["Username", "key", "salt"], [usuario, key, salt])

def añadir_datos(username, data_name, data):
    path = "json/datos.json"
    add(path, ["Username", "Data_name", "Data"], [username, data_name, data])

def añadir_asimetrico(username, user_privada, user_publica):
    path = "json/asimetrico.json"
    add(path, ["Username", "User_privada", "User_publica"], [username, user_privada, user_publica])


def buscar(user, newpassword):
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
    
def guardar_mensaje(user, mensaje):
    print("se ha guardado el mensaje correctamente")