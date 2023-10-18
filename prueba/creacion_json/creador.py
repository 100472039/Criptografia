import json

def crear_json():
    # Crear un diccionario de ejemplo
    datos = []

    # Convertir el diccionario a formato JSON
    json_datos = json.dumps(datos, indent=4)  # indentación para una mejor legibilidad (opcional)

    # Escribir el JSON en un archivo
    with open("datos.json", "w") as archivo_json:
        archivo_json.write(json_datos)

    print("Archivo JSON creado correctamente.")

def add(usuario, contraseña, salt, contraseña_sin_encriptar):
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    try:
        with open("datos.json", "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        datos_existentes = []

    print(datos_existentes)
    
    # Añadir nuevos datos al diccionario existente
    nuevos_datos = {
        "Usuario": usuario,
        "Contraseña": contraseña,
        "Salt": salt,
        "Contraseña sin encriptar": contraseña_sin_encriptar
    }

    datos_existentes.append(nuevos_datos)

    # Escribir el diccionario actualizado de vuelta al archivo JSON
    with open("datos.json", "w") as archivo_json:
        json.dump(datos_existentes, archivo_json, indent=4)

    print("Nuevos datos añadidos al archivo JSON correctamente.")

def add_chat():
    # Cargar el JSON existente desde el archivo o crear un diccionario vacío si el archivo no existe
    try:
        with open("datos.json", "r") as archivo_json:
            datos_existentes = json.load(archivo_json)
    except FileNotFoundError:
        datos_existentes = []

    print(datos_existentes)
    
    # Añadir nuevos datos al diccionario existente
    nuevos_datos = {
        "Usuario": usuario,
        "Contraseña": contraseña,
        "Salt": salt,
        "Contraseña sin encriptar": contraseña_sin_encriptar
    }

    datos_existentes.append(nuevos_datos)

    # Escribir el diccionario actualizado de vuelta al archivo JSON
    with open("datos.json", "w") as archivo_json:
        json.dump(datos_existentes, archivo_json, indent=4)

    print("Nuevos datos añadidos al archivo JSON correctamente.")



#crear_json()
add("Alberto", 1234, "tusalt", "simio")
#add_chat()