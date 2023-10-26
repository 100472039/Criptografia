from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend


# Generar claves asimétricas
privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
publica = privada.public_key()


# Generar clave simétrica
simetrica = Fernet.generate_key()

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
        print(f'Error al descifrar el mensaje o verificar la autenticidad: {Exception}')
        return None


# Ejemplo de uso
mensaje_original = b"Este es un mensaje secreto"
clave_asimetrica = cifrar_con_publica(publica, simetrica)
cifrado, tag = cifrado_simetrico(simetrica, mensaje_original)
descifrado_simetrico(simetrica, cifrado, tag)

    