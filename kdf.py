import os 
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#eso no lo necesitamos todavía
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derivar (password):

    #salt generada aleatoriamente
    salt = os.urandom(16)

    #derive
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key= kdf.derive(password)
    return key, salt;

def verificar(key, salt, newpassword):
    # verify
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )

    try: out=kdf.verify(newpassword, key) 
    except: return False
    else: 
        if out==None:
           return True
        else:
            return False

# #contraseña buena
# password = b"hola"

# #preguntar password
# newpassword = input("Introduzca su contraseña: ")
# newpassword = bytes(newpassword, encoding='utf-8')

# key, salt = derivar(password)
# verificar(key, salt, newpassword)