import os
from django.views import View
from django.views.decorators.http import require_GET
from django.contrib.auth.decorators import login_required
from rest_framework.viewsets import ViewSet
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated

@login_required
@require_GET
def download(request, name):
    return open(name).read()

class JobView(View):
    def post(self, request):
        return os.system(request.POST.get("command"))

class Jobs(ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        return []

    def retrieve(self, request, pk=None):
        return pk

    @action(detail=True, methods=["post"], url_path="execute")
    def execute(self, request, pk=None):
        return os.system(request.data["command"])
