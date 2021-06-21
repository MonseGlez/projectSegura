from django.contrib.auth.forms import UserCreationForm, PasswordResetForm
from django.contrib.auth.models import User
from django.forms import PasswordInput
from django import forms
from gestorContraseñas.utils import enviarMensaje
import logging
import traceback
import sys
from django.contrib.auth.models import User

import re
from django.core.validators import RegexValidator

# Enable logging
logging.basicConfig(level="ERROR")
logger = logging.getLogger()

from gestorContraseñas.models import Credencial


class agregarCredencial(forms.ModelForm):


    nombreCuenta = forms.CharField(label="¿A que sitio pertenece tu cuenta? p. ej. Facebook",  validators=[RegexValidator('^[a-zA-Z_0-9]{5,15}$', message="Solo se aceptan letras, sin espacios, por ejemplo Facebook ó Facebook_1, minimo 5 caracteres, máximo 15")])
    usuarioCuenta = forms.CharField(label="Ingresa tu nombre de usuario:", validators=[RegexValidator('^[a-zA-Z0-9]{5,20}$', message="Solo se aceptan letras,números sin espacios, minimo 5, máximo 20")])
    contraseña = forms.CharField(widget=forms.PasswordInput, label="Ingresa tu contraseña")
    url = forms.URLField(label="Ingresa la URL del sitio p. ej. https://www.facebook.com", required=True,min_length=5,max_length=15)

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
            if len(contraseña) > 50:
                raise forms.ValidationError('La contraseña es muy larga. (max 16 caracteres')

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


class EmailValidationOnForgotPassword(PasswordResetForm):

    def clean_email(self):
        email = self.cleaned_data['email']
        if not User.objects.filter(email__iexact=email, is_active=True).exists():
            msg = ("Este correo no está registrado, por favor registrate.")
            self.add_error('email', msg)
        return email