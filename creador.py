import sys
import json
from kdf import *

path = "json/programa/datos.json"

def abrir_archivo(path):
    try:
        with open(path, "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        datos_existentes = []
    return datos_existentes

def add(path, entradas, valores):
    #comprobar que los valores de entrada son valores
    if len(entradas) != len(valores):
        print("Valores de entrada inválidos")
        return -1
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    datos_existentes = abrir_archivo(path)
    
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

def remove(path, user):
    datos_existentes = abrir_archivo(path)
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"] == user:
            #Eliminar diccionario de la lista
            del datos_existentes[i]
            print("Datos eliminados del archivo JSON correctamente")
            # Escribir el diccionario actualizado de vuelta al archivo JSON
            with open(path, "w") as archivo_json:
                json.dump(datos_existentes, archivo_json, indent=4)
            return True
    return False

def comprobar_duplicados(path, user):
    datos_existentes = abrir_archivo(path)
    eliminados = []
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"] == user:
            eliminados.insert(0, i)
    for i in eliminados:
        del datos_existentes[i]
    # Escribir el diccionario actualizado de vuelta al archivo JSON
    with open(path, "w") as archivo_json:
        json.dump(datos_existentes, archivo_json, indent=4)

def añadir_registro(usuario, key, salt, user_publica):
    path = "json/programa/registro.json"
    add(path, ["Username", "key", "salt", "User_publica"], [usuario, key, salt, user_publica])

def añadir_datos(username, data_name, data, tag):
    path = "json/programa/datos.json"
    add(path, ["Username", "Data_name", "Data", "Tag"], [username, data_name, data, tag])

def añadir_datos_recuperados(username, data_name, data):
    path = "json/usuario/datos_recuperados.json"
    add(path, ["Username", "Data_name", "Data"], [username, data_name, data])

    path="/home/alberto/Documentos/Criptografia/Criptografia/json/usuario/" + data_name + ".mp3"
    with open(path, 'wb') as file:
        file.write(bytes.fromhex(data))

def añadir_certificado(nombre, publica, certificado, padre):
    path = "json/autoridades/certificados.json"
    add(path, ["Username", "User_publica", "Certificado", "Padre"], [nombre, publica, certificado, padre])

def añadir_claves_programa(username, user_privada, user_publica):
    path = "json/programa/claves.json"
    # Comprobar que no hay valores repetidos
    comprobar_duplicados(path, username)
    add(path, ["Username", "User_privada", "User_publica"], [username, user_privada, user_publica])

def añadir_claves_usuario(username, user_privada, user_publica, user_simetrica):
    path = "json/usuario/claves.json"
    # Comprobar que no hay valores repetidos
    comprobar_duplicados(path, username)
    add(path, ["Username", "User_privada", "User_publica", "User_simetrica"], [username, user_privada, user_publica, user_simetrica])

def añadir_user_session_keys(username, simetrica_cifrada, simetrica):
    path = "json/usuario/session_keys.json"
    comprobar_duplicados(path, username)
    add(path, ["Username", "Simetrica_cifrada", "Simetrica"], [username, simetrica_cifrada, simetrica])

def añadir_session_key(username, simetrica):
    path = "json/programa/session_keys.json"
    comprobar_duplicados(path, username)
    add(path, ["Username", "Simetrica"], [username, simetrica])

def remove_session_key(user):
    path = "json/programa/session_keys.json"
    existente = True
    while existente:
        existente = remove(path, user)
    path = "json/usuario/session_keys.json"
    existente = True
    while existente:
        existente = remove(path, user)


def buscar(user, newpassword):
    path = "json/programa/registro.json"
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    datos_existentes = abrir_archivo(path)

    if datos_existentes == []:
        print("No hay datos en el registro")
        return False
    
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"]==user:
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
    
def buscar_publica(user, programa: bool):
    path = "json/usuario/claves.json"
    if programa:
        path = "json/programa/registro.json"
    if user == "programa":
        path = "json/programa/claves.json"
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    datos_existentes = abrir_archivo(path)

    if datos_existentes == []:
        print("No hay datos en el registro")
        return None

    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"]==user:
            return datos_existentes[i]["User_publica"]

def buscar_privada(user):
    path = "json/usuario/claves.json"
    if user == "programa":
        path = "json/programa/claves.json"
    datos_existentes = abrir_archivo(path)
    if datos_existentes == []:
        print("No hay datos en el registro")
        return None
    
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"]==user:
            return datos_existentes[i]["User_privada"]
    
def buscar_simetrica(user):
    path = "json/usuario/claves.json"
    datos_existentes = abrir_archivo(path)
    if datos_existentes == []:
        print("No hay datos en el registro")
        sys.exit(1)
    
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"]==user:
            return datos_existentes[i]["User_simetrica"]

def buscar_session_key(user, programa: bool):
    path = "json/usuario/session_keys.json"
    if programa:
        path = "json/programa/session_keys.json"
    datos_existentes = abrir_archivo(path)
    if datos_existentes == []:
        print("No hay datos en el registro")
        sys.exit(1)
    
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"]==user:
            return datos_existentes[i]["Simetrica"]

def buscar_dato(user, data_name):
    path = "json/programa/datos.json"
    datos_existentes = abrir_archivo(path)
    if datos_existentes == []:
        print("No hay datos en el registro")
    
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"] == user and datos_existentes[i]["Data_name"] == data_name:
            return datos_existentes[i]["Data"]

def buscar_tag(user, data_name):
    path = "json/programa/datos.json"
    datos_existentes = abrir_archivo(path)
    if datos_existentes == []:
        print("No hay datos en el registro")
    
    for i in range(len(datos_existentes)):
        if datos_existentes[i]["Username"] == user and datos_existentes[i]["Data_name"] == data_name:
            return datos_existentes[i]["Tag"]

def guardar_mensaje(user, mensaje):
    print("se ha guardado el mensaje correctamente")