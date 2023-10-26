from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


# Creando claves asimétricas
privada = rsa.generate_private_key(public_exponent=65537,key_size=2048)
publica=privada.public_key()


#generar clave simétrica 
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

# Cifrar simétricamente los datos
def cifrado_simetrico(simetrica, mensaje):
    cipher_suite = Fernet(simetrica)
    cifrado = cipher_suite.encrypt(mensaje)
    print(f'Mensaje cifrado simétricamente: {cifrado}')
    return cifrado

def descifrado_simetrico(simetrica, cifrado):
    cipher_suite = Fernet(simetrica)
    try:
        mensaje = cipher_suite.decrypt(cifrado)
        print(f'Mensaje descifrado simétricamente: {mensaje}')
        return mensaje
    except Exception as e:
        print(f'Error al descifrar el mensaje: {e}')
        return None
    