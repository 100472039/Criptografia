from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
import random



class por_certificar:
    def __init__(self, nombre, privada, publica, provincia, ciudad, padre):
        self.name = nombre
        self.pr = privada
        self.pu = publica
        self.provincia = provincia
        self.ciudad = ciudad
        self.padre = padre
        self.cert = "no hay certificado"
        

class certificado:
    def __init__(self, nombre, publica, cert, padre):
        self.name = nombre
        self.pu = publica
        self.cert = cert
        self.padre = padre

def crear_usuario(name, pr, a, c):
    k = random.randint(0, 100)%4
    if k==0:
        padre = a[3]
        cert_padre=c[3]
    elif k==1:
        padre = a[4]
        cert_padre=c[4]
    elif k==2:
        padre = a[5]
        cert_padre=c[5]
    elif k==3:
        padre = a[6]
        cert_padre=c[6]
    
    user = por_certificar(name, pr, pr.public_key(), "Madrid", "Madrid", padre)
    crear_certificado_usuario(user)
    cert_user=certificado(user.name, user.pu, user.cert, cert_padre)
    print("Certificado del usuario", name, "creado correctamente")
    return cert_user

    
def crear_certificado_usuario(usuario):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, usuario.provincia),
                x509.NameAttribute(NameOID.LOCALITY_NAME, usuario.ciudad),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, usuario.name),
            ])).add_extension(
                x509.SubjectAlternativeName([
                ]),
                critical=False,
            ).sign(usuario.pr, hashes.SHA256())

    usuario.cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        usuario.padre.cert.subject  
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=0), critical=True
    ).sign(usuario.padre.pr, hashes.SHA256(), default_backend())

    return usuario

def crear_autoridades():
    pr0 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    pr1 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    pr2 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    pr3 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    pr4 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    pr5 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    pr6 = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    
    a0=por_certificar("Autoridad Máxima",pr0,pr0.public_key(), "Distrito Federal Central", "Moscú", "Master")
    a1=por_certificar("Graz",pr1,pr1.public_key(), "Styria", "Graz", a0)
    a2=por_certificar("Geneva",pr2,pr2.public_key(), "Canton of Zurich", "Zurich", a0)
    a3=por_certificar("Madrid",pr3,pr3.public_key(), "Madrid", "Madrid", a1)
    a4=por_certificar("Barcelona",pr4,pr4.public_key(), "Cataluña", "Barcelona", a2)
    a5=por_certificar("Bilbao",pr5,pr5.public_key(), "País Vasco", "Bilbao", a1)
    a6=por_certificar("Valencia",pr6,pr6.public_key(), "Comunidad Valenciana", "Valencia", a2)


    autoridades = [a0, a1, a2, a3, a4, a5, a6]
    crear_certificados_autoridades(autoridades)

    c0 = certificado(a0.name, a0.pu, a0.cert, "Master")
    c1 = certificado(a1.name, a1.pu, a1.cert, c0)
    c2 = certificado(a2.name, a2.pu, a2.cert, c0)
    c3 = certificado(a3.name, a3.pu, a3.cert, c1)
    c4 = certificado(a4.name, a4.pu, a4.cert, c2)
    c5 = certificado(a5.name, a5.pu, a5.cert, c1)
    c6 = certificado(a6.name, a6.pu, a6.cert, c2)

    certificados = [c0, c1, c2, c3, c4, c5, c6]

    print("Autoridades y sus certificados creadas correctamente")
    return autoridades, certificados

def crear_certificados_autoridades(autoridades):

    for aut in autoridades:
        if aut.padre == "Master":
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, aut.provincia),
                x509.NameAttribute(NameOID.LOCALITY_NAME, aut.ciudad),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, aut.name),
            ])
            
            aut.cert  = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                aut.pu
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("major host")]),
                critical=False,
            ).sign(aut.pr, hashes.SHA256())


        
        else:
            
            csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
                # Provide various details about who we are.
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, aut.provincia),
                x509.NameAttribute(NameOID.LOCALITY_NAME, aut.ciudad),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, aut.name),
            ])).add_extension(
                x509.SubjectAlternativeName([
                ]),
                critical=False,
            ).sign(aut.pr, hashes.SHA256())

            aut.cert = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                aut.padre.cert.subject  
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            ).sign(aut.padre.pr, hashes.SHA256(), default_backend())

            #subordinada_certificado_pem = subordinada_certificado.public_bytes(serialization.Encoding.PEM)



def cert_correcto(cert, pu):
    try:
        pu.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )    
    except InvalidSignature:
        print("ERROR: CERTIFICADO FALSO")
        return False
    return True


def comprobar_certificado(nodo: certificado):
    if nodo.padre == "Master":
        if cert_correcto(nodo.cert, nodo.pu):
            print("Certificado de", nodo.name, "es válido")
            print("Todos los certificados son correctos")
            return True
    else:
        if cert_correcto(nodo.cert, nodo.padre.pu):
            print("Certificado de", nodo.name, "es válido")
            comprobar_certificado(nodo.padre)
    

a, c = crear_autoridades()

pr0 = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    )

c0=crear_usuario("Alberto", pr0, a, c)
c1=crear_usuario("Agueda", pr0, a, c)



comprobar_certificado(c0)
comprobar_certificado(c1)



