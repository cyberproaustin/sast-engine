"""A second application, with a model whose name the first one also uses.

`Device` is defined here AND in `dcim/models/sites.py`. A decorator naming it says only
`Device`, so which app's model it binds to is not readable, and the key the URL builder
would ask with is unknown -- see the negative in `ipam/views.py`.
"""
from django.db import models


class Prefix(models.Model):
    prefix = models.CharField(max_length=64)


class Device(models.Model):
    name = models.CharField(max_length=100)
