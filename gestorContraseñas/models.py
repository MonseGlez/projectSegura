
# Create your models here.


from django.db import models
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.db.models.signals import post_save
from django import forms
from gestorContraseñas.utils import enviarMensaje
import logging
import traceback
import sys
# Enable logging
logging.basicConfig(level="ERROR")
logger = logging.getLogger()

# Create your models here.


class Usuario(models.Model):
   usuario = models.OneToOneField(User, on_delete=models.CASCADE)
   usuario.email = models.EmailField(('email address'), unique=True)
   # Python 3
   def __str__(self):
       return self.usuario.username

@receiver(post_save, sender=User)
def crear_usuario(sender, instance, created, **kwargs):
   if created:
        Usuario.objects.create(usuario=instance)
@receiver(post_save, sender=User)
def guardar_usuario(sender, instance, **kwargs):
   instance.usuario.save()

class Credencial(models.Model):
    nombreCuenta = models.CharField(max_length=15)
    Usuario = models.ForeignKey(Usuario, on_delete=models.CASCADE , default=None)

    usuarioCuenta = models.CharField(max_length=15)
    contraseña = models.CharField(max_length=100)
    url = models.CharField(max_length=25)

   # def __str__(self):
    #    return self.name

    def clean_contraseña(self):
            contraseña = self.cleaned_data.get('contraseña')
            if len(contraseña) > 100:
                raise forms.ValidationError('La contraseña es muy largo. (max 50 caracteres')
                exc_type, exc_value, exc_traceback = sys.exc_info()
                lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
                mensaje = (''.join('!! ' + line for line in lines))
                enviarMensaje(mensaje)
            return contraseña










