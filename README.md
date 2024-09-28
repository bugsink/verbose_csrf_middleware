# Verbose CSRF Middleware

This is a verbatim copy of the Django CSRF middleware, but it is more verbose in its failures.

This is especially useful when CSRF failures are happening due to some misconfiguration of your server, your reverse
proxy, or some combination thereof.

Django 4.2 introduced various "more strict" CSRF checks, in particular checks on the `Origin` and `Referer` header.
This middleware can help you debug problems with those checks in your setup.

### Usage:

In your `settings.py` file, in the `MIDDLEWARE_CLASSES`, search for this line:

```
    'django.middleware.csrf.CsrfViewMiddleware',  # search this to remove it
```

and then _replace_ it with the line below:

```
    'verbose_csrf_middleware.CsrfViewMiddleware',
```
