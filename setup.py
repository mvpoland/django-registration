from setuptools import setup, find_packages

setup(
    name = "django-registration",
    version = "old_django_apps_version",
    url = 'https://github.com/citylive/django-registration',
    license = 'commercial',
    description = "Django registration",
    author = '',
    packages = find_packages(),
    zip_safe=False,
    include_package_data=True,
    classifiers = [
        'Programming Language :: Python',
        'Operating System :: OS Independent',
    ],
)
