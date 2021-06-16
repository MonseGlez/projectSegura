from django.conf.urls import url
from gestorContraseñas import views
from django.urls import path
from django.contrib.auth import views as auth_views
from django.views.decorators.csrf import csrf_protect
from gestorContraseñas.forms import  EmailValidationOnForgotPassword

urlpatterns = [
   url(r'^registrate/$', csrf_protect(views.registrarUsuario), name='sign_up'),
   path('activar/<uidb64>/<token>',
         views.activar, name='activate'),

    path('password-reset/', csrf_protect(auth_views.PasswordResetView.as_view(form_class=EmailValidationOnForgotPassword,template_name='gestorContraseñas/reset_contraseña.html')),
         name='password_reset'),
    path('password-reset/done/',
         csrf_protect(auth_views.PasswordResetDoneView.as_view(template_name='gestorContraseñas/password_reset_done.html')),
         name='password_reset_done'),
    path('password-reset-confirm/<uidb64>/<token>/',
         csrf_protect(auth_views.PasswordResetConfirmView.as_view(template_name='gestorContraseñas/password_reset_confirm.html')),
         name='password_reset_confirm'),

    path('password-reset-complete/',
         csrf_protect(auth_views.PasswordResetCompleteView.as_view(
             template_name='gestorContraseñas/password_reset_complete.html')
         ),
         name='password_reset_complete')

]

