import json
from kdf import *

path = "json/datos.json"

def crear_json():
    # Crear un diccionario de ejemplo
    datos = []

    # Convertir el diccionario a formato JSON
    json_datos = json.dumps(datos, indent=4)  # indentación para una mejor legibilidad (opcional)

    # Escribir el JSON en un archivo
    with open(path, "w") as archivo_json:
        archivo_json.write(json_datos)

    print("Archivo JSON creado correctamente.")

def add(usuario, contraseña, salt, contraseña_sin_encriptar):
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    try:
        with open(path, "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        datos_existentes = []

    print(datos_existentes)
    
    # Añadir nuevos datos al diccionario existente
    nuevos_datos = {
        "Username": usuario,
        "Password": contraseña,
        "Salt": salt,
        "Unencrypted password": contraseña_sin_encriptar
    }

    datos_existentes.append(nuevos_datos)

    # Escribir el diccionario actualizado de vuelta al archivo JSON
    with open(path, "w") as archivo_json:
        json.dump(datos_existentes, archivo_json, indent=4)

    print("Nuevos datos añadidos al archivo JSON correctamente.")

def registrar(usuario, key, salt):
    path = "json/registro.json"
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    try:
        with open(path, "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        datos_existentes = []
    
    # Añadir nuevos datos al diccionario existente
    nuevos_datos = {
        "Username": usuario,
        "key": key,
        "salt": salt
    }

    datos_existentes.append(nuevos_datos)

    # Escribir el diccionario actualizado de vuelta al archivo JSON
    with open(path, "w") as archivo_json:
        json.dump(datos_existentes, archivo_json, indent=4)

    print("Nuevos datos añadidos al archivo JSON correctamente.")

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