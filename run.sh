#!/bin/bash

sleep 5
python -u manage.py makemigrations
python -u manage.py migrate
python -u manage.py runserver 0.0.0.0:8081
