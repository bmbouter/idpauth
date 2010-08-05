from django.conf import settings
from idpauth import authentication_tools

def context_preprocessor(request):
    d = {}
    institution = authentication_tools.get_institution(request)
    if institution != None:
        d['institution'] = institution
        return d
