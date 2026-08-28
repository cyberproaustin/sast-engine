"""A CSRF decision belongs to the handler that changes state.

The population rule cannot distinguish these views: both class views explicitly remove
CSRF enforcement, and the function view simply accepts Django's default method surface.
The body supplies the missing fact. The exempt POST and the safe-method route each write
persistent state from their entry block; the exempt GET only reads and must stay silent.
"""
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import FormView, View

from .models import Crawl, LongLivedSession


def create_crawl(form):
    return Crawl.objects.create(url=form.cleaned_data["url"])


@method_decorator(csrf_exempt, name="dispatch")
class AddView(FormView):
    def form_valid(self, form):
        crawl = create_crawl(form)
        return JsonResponse({"id": crawl.pk})


@method_decorator(csrf_exempt, name="dispatch")
class ReadOnlyView(View):
    def get(self, request):
        return JsonResponse({"count": Crawl.objects.count()})


def mint_long_lived_session(user):
    session, _ = LongLivedSession.objects.update_or_create(user=user)
    return session.token


@login_required
def app_auth_handoff(request):
    token = mint_long_lived_session(request.user)
    return JsonResponse({"token": token})
