import datetime

from django.shortcuts import render

# Create your views here.
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView, LogoutView
from django.http import HttpResponse, HttpResponseRedirect
from django.utils.http import urlsafe_base64_decode
from gestorContraseñas.forms import SignUpForm, agregarCredencial, compartirCredencial
from django.views.generic import TemplateView, CreateView
from django.shortcuts import render, redirect
from django.shortcuts import get_object_or_404
from gestorContraseñas.models import Credencial
from gestorContraseñas.utils import *
from django.http import HttpResponseServerError, HttpResponseNotFound
from django.db import IntegrityError, DataError
import logging
import traceback
import sys
from django import forms
from django.contrib.auth.hashers import check_password
from os import remove
import json
from django.contrib.auth.models import User
from django.utils.decorators import method_decorator
from axes.decorators import axes_dispatch
from django.views.decorators.csrf import csrf_exempt

# Enable logging
logging.basicConfig(level="ERROR")
logger = logging.getLogger()
# Create your views here


def registrarUsuario(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            usuario = form.cleaned_data.get('first_name')
            password = form.cleaned_data.get('password1')
            enviarCorreo(user, request, form)

            return HttpResponse('Por favor, confirma tu cuenta con el link que se envio a tu correo ')
    else:
        form = SignUpForm()
    return render(request, 'gestorContraseñas/registrate.html', {'form': form})


def activar(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        return error_500(request)
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        return HttpResponse('Gracias por confirmar tu cuenta. Ahora puedes iniciar sesión.>')
    else:
        return HttpResponse('Enlace de activacion erroneo!')


def registrarCredencial(request):
    form = agregarCredencial(request.POST or None)
    try:
        if form.is_valid():
            instance = form.save(commit=False)
            instance.Usuario_id = request.user.id

            instance.contraseña = encrypt(request.user.password.encode('utf-8'), form.cleaned_data['contraseña'].encode('utf-8'))
            if len(instance.contraseña) > 100:
                raise forms.ValidationError('La contraseña es muy largo. (max 100 caracteres')
            else:
                instance.save()
                messages.success(request, 'La cuenta fue agregada!')
                return redirect('/agregar-credencial')

        else:
            context = {'form': form}
            return render(request, 'gestorContraseñas/credencial_form.html', context)
    except DataError:
        return error_500(request)
    except TypeError:
        return error_500(request)
    except ValueError:
        return error_500(request)
    except IntegrityError:
        return error_500(request)


def credencial_detail(request, id):
    credencial = get_object_or_404(Credencial.objects.filter(Usuario_id=request.user.id), id=id)
    contraseña = list(Credencial.objects.filter(id=id).values_list('contraseña', flat=True))
    try:
        credencial.contraseña = decrypt(request.user.password.encode('utf-8'), contraseña[0]).decode()
        return render(request, 'gestorContraseñas/credencial_detail.html', {'credencial': credencial})
    except DataError:
        error_500(request)
    except TypeError:
        error_500(request)
    except ValueError:
        error_500(request)
    except IntegrityError:
        error_500(request)
    except IndexError:
        error_500(request)


def credencial_list(request):

    credenciales = Credencial.objects.filter(Usuario_id=request.user.id)

    return render(request, 'gestorContraseñas/credencial_list.html', {'posts': credenciales})


def compartirCredenciales(request):
    form = compartirCredencial(request.POST or None)
    if form.is_valid():
        usuarioExterno = form.cleaned_data['usuarioExterno']
        correoExterno = User.objects.filter(username=usuarioExterno).values_list('email',flat=True).first()
        contraseña = form.cleaned_data.get('contraseña')
        contraseñaActual = request.user.password
        nombreusuario = request.user.username
        matchcheck = check_password(contraseña, contraseñaActual)
        if matchcheck is not False:
            decrypted =[]
            cuentas =[]
            usuarioCuenta =[]
            contraseñas =  Credencial.objects.filter(Usuario_id=request.user.id).values_list('contraseña')
            credenciales = Credencial.objects.filter(Usuario_id=request.user.id).values_list('nombreCuenta')
            usuario = Credencial.objects.filter(Usuario_id=request.user.id).values_list('usuarioCuenta')

            if credenciales.count() !=0 and contraseñas.count !=0:
                for i in contraseñas:
                    decrypted.append(decrypt(request.user.password.encode('utf-8'), str(i)).decode())
                for n in credenciales:
                    cuentas.append(n)
                for i in usuario:
                    usuarioCuenta.append(i)
                datos = [' Usuario: ',usuarioCuenta,'Cuenta:',cuentas,'Contraseña :',decrypted]
                path = 'llaves/' + nombreusuario + '.txt'
                escribirt_arch(path, str(datos))
                mensaje = 'Hola,' + usuarioExterno + ' , el usuario ' + request.user.username + ' confío en ti, aquí tienes sus credenciales,'
                enviar_mail(correoExterno, path, mensaje)
                remove(path)
                return HttpResponse('OK')
            else:
                return HttpResponse('No existe ninguna credencial!')
        else:
            return HttpResponse('Contraseña Erronea <a href=http://127.0.0.1:8000> regresar </a>')
    else:
        return render(request, 'gestorContraseñas/compartir_credencial.html', {'form': form})




def credencialDelete(request, id):
    context = {}
    credencial = get_object_or_404(Credencial, id=id)
    if request.method == "POST":
        credencial.delete()
        return HttpResponseRedirect("/credencial")
    return render(request, "gestorContraseñas/credencial_delete.html", context)


def credencialUpdate(request, id):
    obj = get_object_or_404(Credencial, id=id)
    form = agregarCredencial(request.POST or None, instance=obj)
    if form.is_valid():
        obj = form.save(commit=False)
        obj.contraseña = encrypt(request.user.password.encode('utf-8'), form.cleaned_data['contraseña'].encode('utf-8'))
        obj.save()
        messages.success(request, "Se ha actualizado correctamente")
        context = {'form': form}
        return render(request, 'gestorContraseñas/credencial_form.html', context)
    else:
        context = {'form': form,
                   'error': 'No se actualizo correctamente'}
        return render(request, 'gestorContraseñas/credencial_form.html', context)


def error_500(request):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    mensaje = ('Error 500'.join('!!' + line for line in lines))
    enviarMensaje(mensaje)
    return HttpResponseServerError('Error en el servidor')


def error_404(request, exception):
    exc_type, exc_value, exc_traceback = sys.exc_info()
    lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    mensaje = ('Error 404'.join('!! \n' + line for line in lines))
    enviarMensaje(mensaje)
    return HttpResponseNotFound('Página no encontrada')


class BienvenidaView(TemplateView):
    template_name = 'gestorContraseñas/bienvenida.html'


@method_decorator(axes_dispatch, name='dispatch')
@method_decorator(csrf_exempt, name='dispatch')
class SignInView(LoginView):
    template_name = 'gestorContraseñas/iniciar_sesion.html'



class SignOutView(LogoutView):
    pass
