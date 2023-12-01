import sys
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
    user_privada_str = user_privada_pem.decode('utf-8')
    user_publica_str = user_publica_pem.decode('utf-8')
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
def cifrar_con_publica(publica, mensaje):
    publica_rsa = serialization.load_pem_public_key(publica, backend=default_backend())
    cifrado = publica_rsa.encrypt(
        mensaje.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # Devuelve mensaje con encrypt
    return cifrado


def descifrar_con_privada(user, cifrado):
    privada = buscar_privada(user)
    privada_bytes = privada.encode('utf-8')
    privada_rsa = serialization.load_pem_private_key(privada_bytes, password=None, backend=default_backend())
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
def cifrado_simetrico(simetrica: bytes, mensaje):
    f = Fernet(simetrica)
    cifrado = f.encrypt(mensaje)

    h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
    h.update(cifrado)
    tag = h.finalize()

    return cifrado, tag


# Descifrar simétricamente los datos y verificar la etiqueta de autenticación
def descifrado_simetrico(simetrica: bytes, cifrado, tag):
    try:
        h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
        h.update(cifrado)
        h.verify(tag)

        f = Fernet(simetrica)
        mensaje = f.decrypt(cifrado)
        return mensaje

    except Exception:
        print('Error al descifrar el mensaje o verificar la autenticidad')
        sys.exit(1)

def generar_simetrico():
    simetrico = Fernet.generate_key()
    simetrico_decode = simetrico.decode()
    return simetrico_decode

def session_keys_generator(user):

    session_key = Fernet.generate_key()
    session_key_decode = session_key.decode()
    añadir_session_key(user, session_key_decode)

    return session_key_decode


def encriptar_mensaje(user, mensaje):
    simetrica = buscar_simetrica(user)
    simetrica_encode = simetrica.encode()
    session_key = buscar_session_key(user, False)
    session_key_encode = session_key.encode()
    # Se encripta el mensaje con la simétrica del usuario
    mensaje_simetrica = cifrado_simetrico(simetrica_encode, mensaje.encode())
    # Se firma el mensaje encriptado con la privada del usuario
    firma = firmar(user, mensaje_simetrica[0])
    # Se encripta el mensaje con la session_key
    mensaje_simetrica_simetrica = cifrado_simetrico(session_key_encode, mensaje_simetrica[0])

    return mensaje_simetrica_simetrica, firma, mensaje_simetrica[1]

def firmar(user, mensaje):
    privada = buscar_privada(user)
    privada_pem=privada.encode()
    # Pasamo de formato pem a key class
    privada_rsa = serialization.load_pem_private_key(
        privada_pem,
        password=None,
        backend=default_backend()
    )

    firma = privada_rsa.sign(
        mensaje,
        padding.PSS(                   
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return firma.hex()


def comprobar_firma(publica, firma, mensaje):
    # Pasamo de formato pem a key class
    publica_rsa = serialization.load_pem_public_key(
        publica,
        backend=default_backend()
    )
    firma=bytes.fromhex(firma)
    try:
        publica_rsa.verify(
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("La firma es válida.")
    except:
        print("La firma no es válida.")
        sys.exit(1)
