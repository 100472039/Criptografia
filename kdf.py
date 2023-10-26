import os 
#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#eso no lo necesitamos todavía
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derivar (password: str):

    password = bytes(password, encoding='utf-8')

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
    return key, salt

def verificar(key, salt, newpassword: str):
    # verify
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    newpassword = bytes(newpassword, encoding='utf-8')
    try: out=kdf.verify(newpassword, key) 
    except: return False
    else: 
        if out==None:
           return True
        else:
            return False

# #contraseña buena
# password = "hola"


# #preguntar password
# newpassword = input("Introduzca su contraseña: ")


# key, salt = derivar(password)
# print(verificar(key, salt, newpassword))