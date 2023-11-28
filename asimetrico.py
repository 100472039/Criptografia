import binascii
import ast

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from creador import *


# Generar claves asimétricas
def generar_asimetrico():
    user_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    user_publica = user_privada.public_key()
    # Convertir los datos a hexadecimal
    user_privada_pem = rsa_pem_private(user_privada)
    user_publica_pem = rsa_pem_public(user_publica)
    #user_privada_hex = user_privada_pem.hex()
    #user_publica_hex = user_publica_pem.hex()
    user_privada_str = user_privada_pem.decode('utf-8')
    user_publica_str = user_publica_pem.decode('utf-8')
    # print(type(user_publica_pem))
    return user_privada_str, user_publica_str

def rsa_pem_private(clave):
    new_clave = clave.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())
    return new_clave

def rsa_pem_public(clave):
    new_clave = clave.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return new_clave


# Mandar asimétricamente la clave simétrica
def cifrar_con_publica(user, mensaje):
    publica = buscar_publica(user)
    publica_bytes = publica.encode('utf-8')
    publica_rsa = serialization.load_pem_public_key(publica_bytes, backend=default_backend())
    cifrado = publica_rsa.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # print("cifrado:\n"+str(cifrado))
    # print("cifrado_hex:\n"+str(cifrado.hex()))
    # Devuelve mensaje con encrypt
    return cifrado


def descifrar_con_privada(user, cifrado):
    privada = buscar_privada(user)
    privada_bytes = privada.encode('utf-8')
    privada_rsa = serialization.load_pem_private_key(privada_bytes, password=None, backend=default_backend())
    # print("Privada_rsa:\n"+str(privada_rsa))
    mensaje = privada_rsa.decrypt(
        cifrado,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensaje


# Cifrar simétricamente los datos con etiqueta de autenticación
def cifrado_simetrico(simetrica, mensaje):
    f = Fernet(simetrica)
    cifrado = f.encrypt(mensaje)

    # print("f:\n"+str(f))
    # print("cifrado:\n"+str(cifrado))
    # print("simetrica:\n"+str(simetrica))

    h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
    h.update(cifrado)
    tag = h.finalize()

    # print(f'Mensaje cifrado simétricamente: {cifrado}')
    # print(f'Etiqueta de autenticación: {tag}')
    return cifrado, tag


# Descifrar simétricamente los datos y verificar la etiqueta de autenticación
def descifrado_simetrico(user, cifrado, tag):

    simetrica = buscar_session_key(user)
    simetrica = simetrica.encode()

    try:
        h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
        h.update(cifrado)
        h.verify(tag)

        f = Fernet(simetrica)
        mensaje = f.decrypt(cifrado)
        print(f'Mensaje descifrado simétricamente:\n {mensaje}')
        return mensaje

    except Exception:
        print('Error al descifrar el mensaje o verificar la autenticidad')
        return None

def session_keys_generator(user):

    session_key = Fernet.generate_key()
    print("session_key:\n"+str(session_key))
    #simetrica_cifrada = cifrar_con_publica(user, simetrica)
    session_key_decode = session_key.decode()
    # print("session_key_decode:\n"+str(session_key_decode))
    añadir_simetrico(user, session_key_decode)

    return session_key_decode
    
    # #se inicia sesión
    # # Generar clave simétrica

    # simetrica = Fernet.generate_key()
    # sim_cifrada=cifrar_con_publica(publica_base, simetrica)
    # #se mandaría simétrica a la base de datos

    # guardado_simetrica(user, sim_cifrada)


def encriptar_mensaje(user, mensaje):
    simetrica = buscar_simetrica(user)
    simetrica_encode = simetrica.encode()
    mensaje_publica = cifrar_con_publica(user, mensaje)
    #mensaje_cifrado, tag=cifrado_simetrico(simetrica, mensaje_cifrado)
    mensaje_publica_simetrica = cifrado_simetrico(simetrica_encode, mensaje_publica)

    return mensaje_publica_simetrica


    # #mandar mensaje

    # mensaje=descifrado_simetrico(simetrica, mensaje_cifrado, tag)
    # #guardar en base
    # guardar_mensaje(user, mensaje)


def generar_hash(user, data_name):
    clave = hashes.Hash(hashes.SHA256(), backend=default_backend())
