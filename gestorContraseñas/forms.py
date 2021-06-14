from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.forms import PasswordInput
from django import forms
from gestorContraseñas.utils import enviarMensaje
import logging
import traceback
import sys
from django.contrib.auth.models import User
# Enable logging
logging.basicConfig(level="ERROR")
logger = logging.getLogger()

from gestorContraseñas.models import Credencial


class agregarCredencial(forms.ModelForm):

    nombreCuenta = forms.CharField(label="¿A que sitio pertenece tu cuenta? p. ej. Facebook", required=True)
    usuarioCuenta = forms.CharField(label="Ingresa tu nombre de usuario:", required=True)
    contraseña = forms.CharField(widget=forms.PasswordInput, label="Ingresa tu contraseña", required=True)
    url = forms.URLField(label="Ingresa la URL del sitio p. ej. https://www.facebook.com", required=True)

    class Meta:
        model = Credencial
        fields =['nombreCuenta','usuarioCuenta', 'contraseña','url']

    widgets = {
        "name": forms.TextInput(attrs={'placeholder': 'Name', 'name': 'Name', 'id': 'common_id_for_inputfields',
                                       'class': 'input-class_name'}),
        "description": forms.TextInput(
            attrs={'placeholder': 'description', 'name': 'description', 'id': 'common_id_for_inputfields',

                   'class': 'input-class_name'}),
        "password": PasswordInput(attrs={'placeholder': '********', 'autocomplete': 'off', 'data-toggle': 'password'}),

    }
    def clean_contraseña(self):
            contraseña = self.cleaned_data.get('contraseña')
            if len(contraseña) > 100:
                raise forms.ValidationError('La contraseña es muy larga. (max 50 caracteres)')
                exc_type, exc_value, exc_traceback = sys.exc_info()
                lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
                mensaje = (''.join('!! ' + line for line in lines))
                enviarMensaje(mensaje)
            return contraseña


class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=140, required=True, label="Nombre")
    last_name = forms.CharField(max_length=140, required=True, label="Apellido")
    email = forms.EmailField(help_text='Requerido, usa un correo válido, que tengas acceso.')

    class Meta:
        model = User
        fields = (
            'username',
            'email',
            'first_name',
            'last_name',
            'password1',
            'password2',



        )

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('¡Email ya registrado!')
        return email

class compartirCredencial(forms.Form):
    usuarios = User.objects.values()
    usuarioExterno = forms.ChoiceField(choices = [], label="Elige un usuario")



    contraseña = forms.CharField(widget=forms.PasswordInput, label= "Por seguridad ingresa tu contraseña nuevamente")

    def __init__(self, *args, **kwargs):
        super(compartirCredencial, self).__init__(*args, **kwargs)
        self.fields['usuarioExterno'].choices = [(x.username, x.get_full_name()) for x in User.objects.all()]
    class Meta:
        fiels = ('usuarioExterno','contraseña')


