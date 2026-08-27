"""The models, so that `Bookmark.objects` is a manager the frontend can render into a
callee spelling rather than an unresolved name."""
from django.db import models


class Bookmark(models.Model):
    url = models.CharField(max_length=2048)
    title = models.CharField(max_length=512)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)


class Bundle(models.Model):
    name = models.CharField(max_length=128)
    owner = models.ForeignKey("auth.User", on_delete=models.CASCADE)


class ApiToken(models.Model):
    label = models.CharField(max_length=128)
    user = models.ForeignKey("auth.User", on_delete=models.CASCADE)
