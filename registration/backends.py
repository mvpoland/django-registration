from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User

from registration.models import RegistrationProfile

class RegistrationBackend(ModelBackend):
    def authenticate(self, activation_key=None):
        if activation_key is None:
            return None

        profiles = RegistrationProfile.objects.filter(activation_key=activation_key)
        if len(profiles) == 0:
            return None

        profile = profiles[0]
        return profile.user

