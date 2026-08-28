"""Where the app label the decorator leaves implicit is actually written down.

Django derives a model's app label from the package its `models` module lives in, and the
decorator reads it from `model._meta.app_label` at import time. The package path is the
only place the label appears in the source.
"""
from django.db import models


class Region(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField()


class Device(models.Model):
    name = models.CharField(max_length=100)
