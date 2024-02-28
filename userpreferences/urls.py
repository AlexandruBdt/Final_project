from django.urls import path

from userpreferences import views

urlpatterns = [
    path('', views.index, name='preferences')
]