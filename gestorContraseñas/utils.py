import sys
import traceback

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
import requests
from django.utils import six
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from  cryptography.hazmat.primitives  import  hashes
from  cryptography.hazmat.primitives.asymmetric  import  padding

def regresar_b_arch(path_archivo):
    contenido = ''
    with open(path_archivo, 'rb') as archivo:
        contenido = archivo.read()
    return contenido

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding

def enviarCorreo(user, request, form):
    current_site = get_current_site(request)
    mail_subject = 'Activa tu cuenta. Haz clic en el enlace'
    message = render_to_string('gestorContraseñas/activate_account.html', {
        'user': user,
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': account_activation_token.make_token(user),
    })
    to_email = form.cleaned_data.get('email')
    email = EmailMessage(
        mail_subject, message, to=[to_email]
    )
    email.send()




class TokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            six.text_type(user.pk) + six.text_type(timestamp) + six.text_type(user.is_active)
        )
account_activation_token = TokenGenerator()

def generar_llave_privada():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

def generar_llave_publica(llave_privada):
    return llave_privada.public_key()





def convertir_llave_privada_bytes(llave_privada):
    """
    Convierte de bytes a PEM
    """
    resultado = llave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()

    )
    return resultado


def convertir_bytes_llave_privada(contenido_binario):
    """
    Convierte de PEM a bytes
    """
    resultado = serialization.load_pem_private_key(
        contenido_binario,
        backend=default_backend(),
        password=None)
    return resultado


def convertir_llave_publica_bytes(llave_publica):
    resultado = llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return resultado


def convertir_bytes_llave_publica(contenido_binario):
    resultado = serialization.load_pem_public_key(
        contenido_binario,
        backend=default_backend())
    return resultado

def convertir_llave_publica_bytes(llave_publica):
    resultado = llave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return resultado


def generar_llave_aes_from_password(password):
    password = password.encode('utf-8')
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data ',
                       backend=default_backend()).derive(password)
    return derived_key
def cifrarOAEP(public_key,message):
    ciphertext1 = public_key.encrypt(
    message ,
    padding.OAEP(
       mgf = padding.MGF1(algorithm = hashes.SHA256 ()),
       algorithm = hashes.SHA256 (),
       label = None))
    return ciphertext1


def descifrarOAEP(private_key , ciphertext1):
    recovered1 = private_key.decrypt(
    ciphertext1 ,
    padding.OAEP(
       mgf=padding.MGF1(algorithm=hashes.SHA256 ()),
       algorithm=hashes.SHA256 (),
       label=None))
    return recovered1
def leer(path):
    archivo = open(path,'rb')
    contenido = archivo.read()
    archivo.close()
    return contenido

def cifrar_llavepub(archivoentrada,archivosalida,llave):
    leerArchivo = leer(archivoentrada)
    archivoPublica = leer(llave)
    llave = convertir_bytes_llave_publica(archivoPublica)
    cifrado = open(archivosalida,'wb')
    contenidoCifrado =(cifrarOAEP(llave, leerArchivo))
    cifrado.write(contenidoCifrado)
    cifrado.close()
def descifrar_llavepriv(archivoentrada,archivosalida,llave):
    archivoPrivada = leer(llave)
    llavePriv = convertir_bytes_llave_privada(archivoPrivada)
    descifrado = open(archivosalida,'wb')
    leerCif  = leer(archivoentrada)
    contenidoDescifrado = (descifrarOAEP(llavePriv,leerCif))
    descifrado.write(contenidoDescifrado)
    descifrado.close()

def cifrar(mensaje, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    cifrador = aesCipher.encryptor()
    cifrado = cifrador.update(mensaje)
    cifrador.finalize()
    return cifrado


def descifrar(cifrado, llave_aes, iv):
    aesCipher = Cipher(algorithms.AES(llave_aes), modes.CTR(iv),
                       backend=default_backend())
    descifrador = aesCipher.decryptor()
    plano = descifrador.update(cifrado)
    descifrador.finalize()
    return plano

def escribirt_arch(path_archivo,contenido):

    with open(path_archivo, 'w') as archivo:
        contenido = archivo.write(contenido)

    return contenido

def enviarMensaje(mensaje):
    requests.post(f"https://api.telegram.org/bot1834739498:AAGRpE5-b3BZRTW39AscK_UAdPHNySAalsI/sendMessage?chat_id=408524307&text={mensaje}")

def enviar_mail(destinatario,file_path,contenido):
    msg = EmailMessage('Archivo Contraseñas', contenido, 'from@email.com',
                       [destinatario])
    msg.content_subtype = "html"
    msg.attach_file(file_path)

    msg.send()