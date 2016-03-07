import datetime
import random
import re

from django.conf import settings
from django.db import models
from django.template.loader import render_to_string
from django.utils.translation import ugettext_lazy as _
from hashlib import sha1 as sha_constructor
from django.contrib.auth import get_user_model
from django.contrib.sites.models import Site


SHA1_RE = re.compile('^[a-f0-9]{40}$')


def generate_activation_key(user):
    """
    Generate an activation key using salt and sha.

    The activation key for the ``RegistrationProfile`` will be a
    SHA1 hash, generated from a combination of the ``User``'s
    username and a random salt.
    """
    salt = sha_constructor(str(random.random())).hexdigest()[:5]
    return sha_constructor(salt+user.username).hexdigest()


class RegistrationManager(models.Manager):
    """
    Custom manager for the ``RegistrationProfile`` model.

    The methods defined here provide shortcuts for account creation
    and activation (including generation and emailing of activation
    keys), and for cleaning out expired inactive accounts.

    """
    def activate_user(self, activation_key, callback=None):
        """
        Validate an activation key and activate the corresponding
        ``User`` if valid.

        If the key is valid and has not expired, return the ``User``
        after activating.

        If the key is not valid or has expired, return ``False``.

        If the key is valid but the ``User`` is already active,
        return ``False``.

        To prevent reactivation of an account which has been
        deactivated by site administrators, the activation key is
        reset to the string ``ALREADY_ACTIVATED`` after successful
        activation.

        The callback parameter can be used for calling a method when
        the user is activated. E.g. one can send a confirmation e-mail
        after the user has been activated.
        """
        # Make sure the key we're trying conforms to the pattern of a
        # SHA1 hash; if it doesn't, no point trying to look it up in
        # the database.
        if SHA1_RE.search(activation_key):
            try:
                profile = self.get(activation_key=activation_key)
            except self.model.DoesNotExist:
                return False
            if not profile.activation_key_expired():
                user = profile.user
                user.is_active = True
                user.save()
                profile.activation_key = self.model.ACTIVATED
                profile.save()

                if callback is not None:
                    callback(user)

                return user
        return False

    def create_inactive_user(self, username, password, email,
                             send_email=True, profile_callback=None, extra_mail_context=None,
                             first_name='', last_name='', template_body='', template_subject=''):
        """
        Create a new, inactive ``User``, generates a
        ``RegistrationProfile`` and email its activation key to the
        ``User``, returning the new ``User``.

        To disable the email, call with ``send_email=False``.

        The activation email will make use of two templates:

        ``registration/activation_email_subject.txt``
            This template will be used for the subject line of the
            email. It receives one context variable, ``site``, which
            is the currently-active
            ``django.contrib.sites.models.Site`` instance. Because it
            is used as the subject line of an email, this template's
            output **must** be only a single line of text; output
            longer than one line will be forcibly joined into only a
            single line.

        ``registration/activation_email.txt``
            This template will be used for the body of the email. It
            will receive three context variables: ``activation_key``
            will be the user's activation key (for use in constructing
            a URL to activate the account), ``expiration_days`` will
            be the number of days for which the key will be valid and
            ``site`` will be the currently-active
            ``django.contrib.sites.models.Site`` instance.

        To enable creation of a custom user profile along with the
        ``User`` (e.g., the model specified in the
        ``AUTH_PROFILE_MODULE`` setting), define a function which
        knows how to create and save an instance of that model with
        appropriate default values, and pass it as the keyword
        argument ``profile_callback``. This function should accept one
        keyword argument:

        ``user``
            The ``User`` to relate the profile to.

        """
        with transaction.atomic():
            User = get_user_model()
            new_user = User.objects.create_user(username, email, password)
            new_user.is_active = False
            new_user.first_name = first_name
            new_user.last_name = last_name
            new_user.save()

            registration_profile = self.create_profile(new_user)

        if profile_callback is not None:
            profile_callback(user=new_user)

        if send_email:
            self.send_activation_email(username, extra_mail_context=extra_mail_context, template_body=template_body, template_subject=template_subject)
        return new_user

    def send_activation_email(self, username, extra_mail_context=None, email=None, template_body=None, template_subject=None):
        from django.core.mail import send_mail

        if not template_body or template_body == '':
            template_body = 'registration/activation_email.txt'
        if not template_subject or template_subject == '':
            template_subject = 'registration/activation_email_subject.txt'

        User = get_user_model()
        user = User.objects.get(username=username)
        registration_profile = self.get(user=user)

        current_site = Site.objects.get_current()

        if extra_mail_context is None:
            extra_mail_context = {}
        context = extra_mail_context
        context.update({'site': current_site, 'user': user})

        subject = render_to_string(template_subject,
                                   context)
        # Email subject *must not* contain newlines
        subject = ''.join(subject.splitlines())

        context.update({ 'username': username,
                         'activation_key': registration_profile.activation_key,
                         'expiration_days': settings.ACCOUNT_ACTIVATION_DAYS,
                         'site': current_site })
        message = render_to_string(template_body,
                                   context)

        if email is None or email.strip() == u'':
            email = user.email

        if not email.strip() == u'':
            send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

    def create_profile(self, user):
        """
        Create a ``RegistrationProfile`` for a given
        ``User``, and return the ``RegistrationProfile``.
        """
        return self.create(user=user, activation_key=generate_activation_key(user))

    def delete_expired_users(self):
        """
        Remove expired instances of ``RegistrationProfile`` and their
        associated ``User``s.

        Accounts to be deleted are identified by searching for
        instances of ``RegistrationProfile`` with expired activation
        keys, and then checking to see if their associated ``User``
        instances have the field ``is_active`` set to ``False``; any
        ``User`` who is both inactive and has an expired activation
        key will be deleted.

        It is recommended that this method be executed regularly as
        part of your routine site maintenance; this application
        provides a custom management command which will call this
        method, accessible as ``manage.py cleanupregistration``.

        Regularly clearing out accounts which have never been
        activated serves two useful purposes:

        1. It alleviates the ocasional need to reset a
           ``RegistrationProfile`` and/or re-send an activation email
           when a user does not receive or does not act upon the
           initial activation email; since the account will be
           deleted, the user will be able to simply re-register and
           receive a new activation key.

        2. It prevents the possibility of a malicious user registering
           one or more accounts and never activating them (thus
           denying the use of those usernames to anyone else); since
           those accounts will be deleted, the usernames will become
           available for use again.

        If you have a troublesome ``User`` and wish to disable their
        account while keeping it in the database, simply delete the
        associated ``RegistrationProfile``; an inactive ``User`` which
        does not have an associated ``RegistrationProfile`` will not
        be deleted.

        """
        for profile in self.all():
            if profile.activation_key_expired():
                user = profile.user
                if not user.is_active:
                    user.delete()


class RegistrationProfile(models.Model):
    """
    A simple profile which stores an activation key for use during
    user account registration.

    Generally, you will not want to interact directly with instances
    of this model; the provided manager includes methods
    for creating and activating new accounts, as well as for cleaning
    out accounts which have never been activated.

    While it is possible to use this model as the value of the
    ``AUTH_PROFILE_MODULE`` setting, it's not recommended that you do
    so. This model's sole purpose is to store data temporarily during
    account registration and activation, and a mechanism for
    automatically creating an instance of a site-specific profile
    model is provided via the ``create_inactive_user`` on
    ``RegistrationManager``.

    """
    ACTIVATED = u"ALREADY_ACTIVATED"

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, verbose_name=_('user'))
    activation_key = models.CharField(_('activation key'), max_length=40)

    objects = RegistrationManager()

    class Meta:
        verbose_name = _('registration profile')
        verbose_name_plural = _('registration profiles')

    def __unicode__(self):
        return u"Registration information for %s" % self.user

    def get_has_activated(self):
        return self.activation_key == self.ACTIVATED
    has_activated = property(get_has_activated)

    def activation_key_expired(self):
        """
        Determine whether this ``RegistrationProfile``'s activation
        key has expired, returning a boolean -- ``True`` if the key
        has expired.

        Key expiration is determined by a two-step process:

        1. If the user has already activated, the key will have been
           reset to the string ``ALREADY_ACTIVATED``. Re-activating is
           not permitted, and so this method returns ``True`` in this
           case.

        2. Otherwise, the date the user signed up is incremented by
           the number of days specified in the setting
           ``ACCOUNT_ACTIVATION_DAYS`` (which should be the number of
           days after signup during which a user is allowed to
           activate their account); if the result is less than or
           equal to the current date, the key has expired and this
           method returns ``True``.

        """
        if settings.ACCOUNT_ACTIVATION_DAYS > 0:
            expiration_date = datetime.timedelta(days=settings.ACCOUNT_ACTIVATION_DAYS)
            return self.activation_key == self.ACTIVATED or \
                   (self.user.date_joined + expiration_date <= datetime.datetime.now())
        else:
            return self.activation_key == self.ACTIVATED

    activation_key_expired.boolean = True
