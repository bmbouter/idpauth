from functools import wraps

from django.http import HttpResponseRedirect
from django.utils.decorators import available_attrs
from django.utils.http import urlquote

def idpauth_login_required(login_url=None):

    test_func = lambda u: u.is_authenticated()

    if not login_url:
        login_url = reverse('idpauth.determine_login')

    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            if test_func(request.user):
                return view_func(request, *args, **kwargs)
            path = urlquote(request.build_absolute_uri())
            tup = login_url, "next", path
            return HttpResponseRedirect("%s?%s=%s" % tup)
        return wraps(view_func, assigned=available_attrs(view_func))(_wrapped_view)
    return decorator
