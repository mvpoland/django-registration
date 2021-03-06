"""
Forms and validation code for user registration.

"""

from django import forms
from django.contrib.auth import get_user_model
from django.utils.translation import ugettext_lazy as _

from registration.models import RegistrationProfile


# I put this on all required fields, because it's easier to pick up
# on them with CSS or JavaScript if they have a class of "required"
# in the HTML. Your mileage may vary. If/when Django ticket #3515
# lands in trunk, this will no longer be necessary.
attrs_dict = { 'class': 'required' }

tos_agreement = _(u'I have read and agreed to the <a rel="external" href="/en/conditions/terms/">Terms of Service</a>')

class RegistrationForm(forms.Form):
    """
    Form for registering a new user account.

    Validates that the requested username is not already in use, and
    requires the password to be entered twice to catch typos.

    Subclasses should feel free to add any additional validation they
    need, but should either preserve the base ``save()`` or implement
    a ``save()`` which accepts the ``profile_callback`` keyword
    argument and passes it through to
    ``RegistrationProfile.objects.create_inactive_user()``.

    """
    username = forms.RegexField(regex=r'^\w+$',
                                max_length=30,
                                widget=forms.TextInput(attrs=attrs_dict),
                                error_messages={'invalid': _(u'Username can only contain alphanumeric characters and underscores')},
                                label=_(u'Username'))
    email = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict,
                                                               maxlength=75)),
                             label=_(u'Email'))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_(u'Password'))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_(u'Password (again)'))

    def clean_username(self):
        """
        Validate that the username is alphanumeric and is not already
        in use.

        """
        User = get_user_model()
        try:
            user = User.objects.get(username__iexact=self.cleaned_data['username'])
        except User.DoesNotExist:
            return self.cleaned_data['username']
        raise forms.ValidationError(_(u'This username is already taken. Please choose another.'))

    def clean(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.

        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise forms.ValidationError(_(u'You must type the same password each time'))
        return self.cleaned_data

    def save(self, profile_callback=None, extra_mail_context={}, template_body='', template_subject='', send_email=True):
        """
        Create the new ``User`` and ``RegistrationProfile``, and
        returns the ``User``.

        This is essentially a light wrapper around
        ``RegistrationProfile.objects.create_inactive_user()``,
        feeding it the form data and a profile callback (see the
        documentation on ``create_inactive_user()`` for details) if
        supplied.

        """
        new_user = RegistrationProfile.objects.create_inactive_user(username=self.cleaned_data['username'],
                                                                    password=self.cleaned_data['password1'],
                                                                    email=self.cleaned_data['email'],
                                                                    send_email=False,
                                                                    profile_callback=profile_callback,
                                                                    extra_mail_context=extra_mail_context,
                                                                    template_body=template_body,
                                                                    template_subject=template_subject)
        return new_user

class RegistrationFormDoubleEmail(forms.Form):
    """
    Form for registering a new user account.

    Validates that the requested username is not already in use, and
    requires the password to be entered twice to catch typos.

    Subclasses should feel free to add any additional validation they
    need, but should either preserve the base ``save()`` or implement
    a ``save()`` which accepts the ``profile_callback`` keyword
    argument and passes it through to
    ``RegistrationProfile.objects.create_inactive_user()``.

    """
    username = forms.RegexField(regex=r'^\w+$',
                                max_length=30,
                                widget=forms.TextInput(attrs=attrs_dict),
                                error_messages={'invalid': _(u'Username can only contain alphanumeric characters and underscores')},
                                label=_(u'Username'))
    email1 = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict, maxlength=75)), label=_(u'Email'))
    email2 = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict, maxlength=75)), label=_(u'Email (again)'))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_(u'Password'))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_(u'Password (again)'))

    def clean_username(self):
        """
        Validate that the username is alphanumeric and is not already
        in use.

        """
        User = get_user_model()
        try:
            user = User.objects.get(username__iexact=self.cleaned_data['username'])
        except User.DoesNotExist:
            return self.cleaned_data['username']
        raise forms.ValidationError(_(u'This username is already taken. Please choose another.'))

    def clean_email1(self):
        """
        Validate that the supplied email address is unique for the
        site.

        """
        User = get_user_model()
        if User.objects.filter(email__iexact=self.cleaned_data['email1']).count() > 0:
            raise forms.ValidationError(_(u'This email address is already in use. Please supply a different email address.'))
        return self.cleaned_data['email1']

    def clean(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.

        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise forms.ValidationError(_(u'You must type the same password each time'))
        if 'email1' in self.cleaned_data and 'email2' in self.cleaned_data:
            if self.cleaned_data['email1'] != self.cleaned_data['email2']:
                raise forms.ValidationError(_(u'You must type the same email address each time'))
        return self.cleaned_data

    def save(self, profile_callback=None, extra_mail_context={}, send_mail=True):
        """
        Create the new ``User`` and ``RegistrationProfile``, and
        returns the ``User``.

        This is essentially a light wrapper around
        ``RegistrationProfile.objects.create_inactive_user()``,
        feeding it the form data and a profile callback (see the
        documentation on ``create_inactive_user()`` for details) if
        supplied.

        """
        new_user = RegistrationProfile.objects.create_inactive_user(username=self.cleaned_data['username'],
                                                                    password=self.cleaned_data['password1'],
                                                                    email=self.cleaned_data['email1'],
                                                                    profile_callback=profile_callback,
                                                                    extra_mail_context=extra_mail_context,
                                                                    send_email=send_mail)
        return new_user


class RegistrationFormTermsOfService(RegistrationForm):
    """
    Subclass of ``RegistrationForm`` which adds a required checkbox
    for agreeing to a site's Terms of Service.

    """
    tos = forms.BooleanField(widget=forms.CheckboxInput(attrs=attrs_dict),
                             label=tos_agreement,
                             error_messages={ 'required': _(u"You must agree to the terms to register") })

class RegistrationFormDoubleEmailTermsOfService(RegistrationFormDoubleEmail):
    """
    Subclass of ``RegistrationForm`` which adds a required checkbox
    for agreeing to a site's Terms of Service.

    """
    tos = forms.BooleanField(widget=forms.CheckboxInput(attrs=attrs_dict),
                             label=tos_agreement,
                             error_messages={ 'required': _(u"You must agree to the terms to register") })

class SimpleRegistrationForm(forms.Form):
    email1 = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict, maxlength=75)), label=_(u'Email'))
    email2 = forms.EmailField(widget=forms.TextInput(attrs=dict(attrs_dict, maxlength=75)), label=_(u'Email (again)'))
    password1 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_(u'Password'))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs=attrs_dict, render_value=False),
                                label=_(u'Password (again)'))

    def clean_email1(self):
        """
        Validate that the supplied email address is unique for the
        site.

        """
        User = get_user_model
        if User.objects.filter(email__iexact=self.cleaned_data['email1']).count() > 0:
            raise forms.ValidationError(_(u'This email address is already in use. Please supply a different email address.'))
        return self.cleaned_data['email1']

    def clean(self):
        """
        Verifiy that the values entered into the two password fields
        match. Note that an error here will end up in
        ``non_field_errors()`` because it doesn't apply to a single
        field.

        """
        if 'password1' in self.cleaned_data and 'password2' in self.cleaned_data:
            if self.cleaned_data['password1'] != self.cleaned_data['password2']:
                raise forms.ValidationError(_(u'You must type the same password each time'))
        if 'email1' in self.cleaned_data and 'email2' in self.cleaned_data:
            if self.cleaned_data['email1'] != self.cleaned_data['email2']:
                raise forms.ValidationError(_(u'You must type the same email address each time'))
        return self.cleaned_data

    def save(self, profile_callback=None, extra_mail_context={}, send_mail=True):
        """
        Create the new ``User`` and ``RegistrationProfile``, and
        returns the ``User``.

        This is essentially a light wrapper around
        ``RegistrationProfile.objects.create_inactive_user()``,
        feeding it the form data and a profile callback (see the
        documentation on ``create_inactive_user()`` for details) if
        supplied.

        """
        User = get_user_model()
        username = self.cleaned_data['email1'].split('@')[0]
        # username has max length of 30, so we remove 2 chars for double digits
        username = username[:28]
        exists = lambda p: User.objects.filter(username__iexact=p).count() > 0

        if exists(username):
            counter = 1
            new_username = '%s%i' % (username, counter)
            while exists(new_username):
                counter += 1
                newusername = '%s%i' % (username, counter)
            username = new_username

        new_user = RegistrationProfile.objects.create_inactive_user(username=username,
                                                                    password=self.cleaned_data['password1'],
                                                                    email=self.cleaned_data['email1'],
                                                                    profile_callback=profile_callback,
                                                                    extra_mail_context=extra_mail_context,
                                                                    send_email=send_mail)
        return new_user

class SimpleRegistrationFormTermsOfService(SimpleRegistrationForm):
    """
    Subclass of ``RegistrationForm`` which adds a required checkbox
    for agreeing to a site's Terms of Service.

    """
    tos = forms.BooleanField(widget=forms.CheckboxInput(attrs=attrs_dict),
                             label=tos_agreement,
                             error_messages={ 'required': _(u"You must agree to the terms to register") })

class RegistrationFormUniqueEmail(RegistrationForm):
    """
    Subclass of ``RegistrationForm`` which enforces uniqueness of
    email addresses.

    """
    def clean_email(self):
        """
        Validate that the supplied email address is unique for the
        site.

        """
        User = get_user_model()
        if User.objects.filter(email__iexact=self.cleaned_data['email']).count() > 0:
            raise forms.ValidationError(_(u'This email address is already in use. Please supply a different email address.'))
        return self.cleaned_data['email']


class RegistrationFormNoFreeEmail(RegistrationForm):
    """
    Subclass of ``RegistrationForm`` which disallows registration with
    email addresses from popular free webmail services; moderately
    useful for preventing automated spam registrations.

    To change the list of banned domains, subclass this form and
    override the attribute ``bad_domains``.

    """
    bad_domains = ['aim.com', 'aol.com', 'email.com', 'gmail.com',
                   'googlemail.com', 'hotmail.com', 'hushmail.com',
                   'msn.com', 'mail.ru', 'mailinator.com', 'live.com']

    def clean_email(self):
        """
        Check the supplied email address against a list of known free
        webmail domains.

        """
        email_domain = self.cleaned_data['email'].split('@')[1]
        if email_domain in self.bad_domains:
            raise forms.ValidationError(_(u'Registration using free email addresses is prohibited. Please supply a different email address.'))
        return self.cleaned_data['email']
