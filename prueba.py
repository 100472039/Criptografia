from asimetrico import *

privada_user = rsa.generate_private_key(public_exponent=65537, key_size=2048)
publica_user = privada_user.public_key()

mensaje="Hola me llamo Agueda"

cifrado=cifrar_con_publica(publica_user, mensaje.encode())
print("cifrado es", cifrado)

nuevo_mensaje=descifrar_con_privada(cifrado, privada_user)
print("El mensaje descifrado es: ", nuevo_mensaje.decode())
