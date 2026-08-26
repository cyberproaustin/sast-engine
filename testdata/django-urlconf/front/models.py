from django.db import models


class Check(models.Model):
    code = models.UUIDField()
    name = models.CharField(max_length=100)
