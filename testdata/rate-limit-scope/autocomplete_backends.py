import requests


def remote():
    reply = requests.get("https://suggest.example.test/complete")
    return reply.text


def mirror():
    reply = requests.get("https://mirror.example.test/complete")
    return reply.text
