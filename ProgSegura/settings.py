"""
Django settings for ProgSegura project.

Generated by 'django-admin startproject' using Django 3.2.4.

For more information on this file, see
https://docs.djangoproject.com/en/3.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.2/ref/settings/
"""


from pathlib import Path
import os
#import environ
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

#env = environ.Env()
#env.read_env(env.str('ENV_PATH', '.env'))
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
def get_env_variable(var_name):
    try:
        if var_name == 'DB_NAME':
            return os.environ[var_name].encode('latin')
        return os.environ[var_name]
    except KeyError:\
            error_msg = "set the %s environment variable" % [var_name]
    raise ImproperlyConfigured(error_msg)

LOG_TO_TELEGRAM_BOT_TOKEN = '1834739498:AAGRpE5-b3BZRTW39AscK_UAdPHNySAalsI'
# Build paths inside the project like this: BASE_DIR / 'subdir'.
#BASE_DIR = Path(__file__).resolve().parent.parent
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-mee1c5@ugk8d7$wi(4h1p#ubc^zcjsass8^=o*b5t@q@w!3oq2'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []
#Django Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'telegram_log': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django_log_to_telegram.log.AdminTelegramHandler',

            'bot_token': LOG_TO_TELEGRAM_BOT_TOKEN,
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['telegram_log'],
            'level': 'ERROR',
            'formatter': 'verbose',

            'propagate': True,
        },
    },
}


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'gestorContraseñas.apps.GestorcontraseñasConfig',
    'django_log_to_telegram',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ProgSegura.urls'
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        #'DIRS': [BASE_DIR / 'templates']
        'DIRS': [TEMPLATE_DIR, ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]
TEMPLATE_DIRS = (
        os.path.join(PROJECT_ROOT, "progSegura/gestorContraseñas/templates/"),
    )


WSGI_APPLICATION = 'ProgSegura.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
            'NAME': 'gestorcontraseñas',
            'USER': 'admin',
            'PASSWORD': 'r3d35y53rv1c105',
            'HOST': '127.0.0.1',
            'PORT': '3306',
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'es-mx'

TIME_ZONE = 'America/Mexico_City'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = os.path.abspath(os.path.join(os.path.dirname(BASE_DIR), 'static'))

# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = '/'
LOGOUT_REDIRECT_URL = '/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 15 * 60
LOGIN_REDIRECT_URL ='/'


#una cuenta por correo
ACCOUNT_UNIQUE_EMAIL=True

#Email
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'monserrat.gonzalez95@gmail.com'
EMAIL_HOST_PASSWORD = 'SkywardSword1'
#EMAIL_HOST_PASSWORD = get_env_variable('EMAIL_HOST_PASSWORD')
EMAIL_PORT = 587
