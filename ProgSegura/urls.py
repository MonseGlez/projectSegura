"""ProgSegura URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.contrib import admin
from django.conf.urls import url
from gestorContraseñas.views import BienvenidaView, SignOutView, SignInView
from django.views.decorators.csrf import csrf_protect
from django.urls import path, include
from gestorContraseñas import views
from django.contrib.auth.decorators import login_required

from django.conf.urls import handler404
from django.conf.urls import handler500
from gestorContraseñas.views import error_500,error_404, credencialUpdate,credencialDelete
urlpatterns = [

   path('admin/', admin.site.urls),
   url(r'^$', csrf_protect(BienvenidaView.as_view()), name='bienvenida'),
   path('', include('gestorContraseñas.urls')),
   #url(r'^credencial_detail/(?P<pk>\d+)$', CredencialDetail.as_view(), name='credencial_detail'),
   url(r'^credencial_detail/(?P<id>\d+)$', (login_required(views.credencial_detail)), name='credencial_detail'),
   path('credencial/', csrf_protect(login_required(views.credencial_list)), name='credencial_list'),
   url(r'^cerrar-sesion/$',csrf_protect(login_required(SignOutView.as_view())), name='sign_out'),
   url(r'^inicia-sesion/$', csrf_protect((SignInView.as_view())), name='sign_in'),
   url(r'^agregar-credencial/$', csrf_protect(login_required(views.registrarCredencial)), name='registrarCredencial'),
   url(r'^(?P<id>\d+)/edit/$', csrf_protect(login_required(credencialUpdate)),name='editar-credencial'),
   url(r'^compartir_credencial/$', (login_required(views.compartirCredenciales)), name='credencial_compartir'),
   path('delete/<id>/',login_required(credencialDelete),name='credencial_delete'),

]
handler404 = error_404
handler500 = error_500
