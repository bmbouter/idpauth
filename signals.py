from django.conf import settings
from django.core.mail import send_mail

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
        if len(user) == 1:
            instance.username = 'local++' + instance.username
            instance.save()
            log.debug(instance.username)
        if settings.SEND_EMAIL_ON_USER_CREATION:
            send_mail(settings.EMAIL_SUBJECT, settings.EMAIL_MESSAGE, settings.FROM_EMAIL_ADDRESS,
                    [user[1]], fail_silently=True)

