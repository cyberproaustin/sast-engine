"""The admin's own view. Nothing here is registered by a hook."""


class HomeView:
    def get(self, request):
        return {"template": "home.html"}
