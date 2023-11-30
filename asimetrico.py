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
def cifrado_simetrico(simetrica, mensaje):
    f = Fernet(simetrica)
    cifrado = f.encrypt(mensaje)

    h = hmac.HMAC(simetrica, hashes.SHA256(), backend=default_backend())
    h.update(cifrado)
    tag = h.finalize()

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
        # print(f'Mensaje descifrado simétricamente:\n{mensaje}')
        return mensaje

    except Exception:
        print('Error al descifrar el mensaje o verificar la autenticidad')
        return None

def session_keys_generator(user):

    session_key = Fernet.generate_key()
    # print("session_key:\n"+str(session_key))
    session_key_decode = session_key.decode()
    añadir_simetrico(user, session_key_decode)

    return session_key_decode


def encriptar_mensaje(user, mensaje):
    simetrica = buscar_simetrica(user)
    simetrica_encode = simetrica.encode()
    mensaje_publica = cifrar_con_publica(user, mensaje)
    # Se firma el mensaje encriptado con la pública del usuario
    firma = firmar(user, mensaje_publica)
    # mensaje_cifrado, tag=cifrado_simetrico(simetrica, mensaje_cifrado)
    # print("simetrica_encode:\n"+str(simetrica_encode))
    # print("mensaje_publica:\n"+str(mensaje_publica))
    mensaje_publica_simetrica = cifrado_simetrico(simetrica_encode, mensaje_publica)
    # print("mensaje_publica_simetrica:\n"+str(mensaje_publica_simetrica[0])+"\n"+str(mensaje_publica_simetrica[1]))


    return mensaje_publica_simetrica, firma


    # #mandar mensaje

    # mensaje=descifrado_simetrico(simetrica, mensaje_cifrado, tag)
    # #guardar en base
    # guardar_mensaje(user, mensaje)


def generar_hash(user, data_name):
    clave = hashes.Hash(hashes.SHA256(), backend=default_backend())

def firmar(user, mensaje):
    print("mensaje de entrada en firmar:\n"+str(mensaje))
    #from hex to pem
    #privada_pem=bytes.fromhex(privada_hex)
    privada = buscar_privada(user)
    privada_pem=privada.encode()
    #from pem to key class
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
    print("mensaje de salida en firmar:\n"+str(mensaje))
    return firma.hex()


def comprobar_firma(user, firma, mensaje):
    print("mensaje de entrada en comprobar firma:\n"+str(mensaje))
    #from hex to pem
    #publica_pem=bytes.fromhex(publica_hex)
    publica = buscar_publica(user)
    publica_pem=publica.encode()
    #from pem to key class  
    publica_rsa = serialization.load_pem_public_key(
        publica_pem,
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
        print("mensaje de salida en comprobar firma:\n"+str(mensaje))
        #return True
    except:
        print("La firma no es válida.")
        print("mensaje de salida en comprobar firma:\n"+str(mensaje))
        sys.exit(1)
