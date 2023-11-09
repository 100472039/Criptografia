from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from creador import *


# Generar claves asimétricas
privada_base = rsa.generate_private_key(public_exponent=65537, key_size=2048)
publica_base = privada_base.public_key()


# Mandar asimétricamente la clave simétrica
def cifrar_con_publica(publica, mensaje):
    cifrado = publica.encrypt(
        mensaje,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cifrado


def descifrar_con_privada(cifrado, privada):
    mensaje = privada.decrypt(
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

    h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
    h.update(cifrado)
    tag = h.finalize()

    print(f'Mensaje cifrado simétricamente: {cifrado}')
    print(f'Etiqueta de autenticación: {tag}')
    return cifrado, tag


# Descifrar simétricamente los datos y verificar la etiqueta de autenticación
def descifrado_simetrico(simetrica, cifrado, tag):

    try:
        h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
        h.update(cifrado)
        h.verify(tag)

        f = Fernet(simetrica)
        mensaje = f.decrypt(cifrado)
        print(f'Mensaje descifrado simétricamente: {mensaje}')
        return mensaje

    except Exception:
        print('Error al descifrar el mensaje o verificar la autenticidad')
        return None

def session_keys(user):
    #se inicia sesión
    # Generar clave simétrica

    simetrica = Fernet.generate_key()
    sim_cifrada=cifrar_con_publica(publica_base, simetrica)
    #se mandaría simétrica a la base de datos

    guardado_simetrica(user, sim_cifrada)


def encriptar_mensaje(user, mensaje, pu_user, simetrica):
    mensaje_cifrado=cifrar_con_publica(pu_user, mensaje)
    mensaje_cifrado, tag=cifrado_simetrico(simetrica, mensaje_cifrado)

    #mandar mensaje

    mensaje=descifrado_simetrico(simetrica, mensaje_cifrado, tag)
    #guardar en base
    guardar_mensaje(user, mensaje)



    