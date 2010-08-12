from django.conf import settings
from idpauth import authentication_tools

def context_preprocessor(request):
    d = {}
    institution = authentication_tools.get_institution(request)
    username = request.user.username.split("++")
    if len(username) == 2:
        d['username'] = username[1]
    else:
        d['username'] = username[0]

    if institution != None:
        d['institution'] = institution
        return d
