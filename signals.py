from django.conf import settings
from django.core.mail import send_mail

from opus.lib import log
log = log.getLogger()

def set_identityprovider_type(sender, instance, **kwargs):
    idp_type = sender.__name__.split('IdentityProvider')[1].lower()
    if idp_type == 'openid':
        instance.type = 'openid'
    elif idp_type == 'local':
        instance.type = 'local'
    elif idp_type == 'ldap':
        instance.type = 'ldap'
    else:
        instance.type = ''

def add_local_identifier(sender, instance, created, **kwargs):
    if created:
        user = instance.username.split('++')
        if settings.SEND_EMAIL_ON_USER_CREATION:
            log.debug("sending email")
            send_mail(settings.EMAIL_SUBJECT, settings.EMAIL_MESSAGE + "  " + user[0], settings.FROM_EMAIL_ADDRESS,
                    [settings.EMAIL_TO], fail_silently=False)
            log.debug("Email sent")

