from django.urls import path, include
from rest_framework.routers import SimpleRouter
from .views import download, JobView, Jobs

router = SimpleRouter()
router.register("jobs", Jobs, basename="jobs")
urlpatterns = [
    path("download/<path:name>", download),
    path("job/", JobView.as_view()),
    path("", include(router.urls)),
]
