"""A whole remote input read, and the same read with an application-written bound."""

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.routers import SimpleRouter


MAX_UPLOAD_BYTES = 1024 * 1024


class UploadViewSet(viewsets.GenericViewSet):
    @action(methods=["post"], detail=False, url_path="whole")
    def whole(self, request):
        upload = request.FILES.get("file")
        content = upload.read()
        return Response({"size": len(content)})

    @action(methods=["post"], detail=False, url_path="bounded")
    def bounded(self, request):
        upload = request.FILES.get("file")
        content = upload.read(MAX_UPLOAD_BYTES)
        return Response({"size": len(content)})


router = SimpleRouter()
router.register("uploads", UploadViewSet, basename="uploads")
