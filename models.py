from django.db import models
from django.db.models.signals import pre_save, post_save
from django.contrib.auth.models import Group, User, UserManager

from idpauth import signals

class IdentityProvider(models.Model):
    """Identity provider base class."""
    institution = models.CharField(max_length=60, primary_key=True)
    name = models.CharField(max_length=60, unique=True)
    type = models.CharField(max_length=64, editable=False, blank=True)
    groups = models.ManyToManyField(Group, blank=True)

    class Meta:
        unique_together = ("type", "institution")
    
    def __str__(self):
        return self.name


class IdentityProviderLDAP(IdentityProvider):
    url = models.CharField("Server Url",max_length=60)
    bind_base = models.CharField("Bind Base", max_length=128)
    distinguished_name = models.CharField("Bind Distinguished Name", max_length=128, unique=True, blank=True)
    ssl_option = models.BooleanField("Require SSl Certificate", default=False)
    group_retrieval_string = models.CharField("User groups retrieval string", max_length=128, blank=True) 

    class Meta:
        verbose_name = "LDAP Identity Provider"


class UserProfile(models.Model):
    user = models.ForeignKey(User, unique=True)
    ldap_roles = models.TextField("User's LDAP Roles", editable=False, blank=True)


class IdentityProviderLocal(IdentityProvider):
    class Meta:
        verbose_name = "Local Identity Provider"


class IdentityProviderOpenID(IdentityProvider):        
    class Meta:
        verbose_name = "OpenID Identity Provider"


class IdentityProviderShibboleth(IdentityProvider):
    class Meta:
        verbose_name = "Shibboleth Identity Provider"


####### OpenID Required Models ##############
class Nonce(models.Model):
    server_url = models.URLField()
    timestamp  = models.IntegerField()
    salt       = models.CharField( max_length=50 )

    def __unicode__(self):
        return "Nonce: %s" % self.nonce


class Association(models.Model):
    server_url = models.TextField(max_length=2047)
    handle = models.CharField(max_length=255)
    secret = models.TextField(max_length=255) # Stored base64 encoded
    issued = models.IntegerField()
    lifetime = models.IntegerField()
    assoc_type = models.TextField(max_length=64)

    def __unicode__(self):
        return "Association: %s, %s" % (self.server_url, self.handle)


pre_save.connect(signals.set_identityprovider_type, sender=IdentityProviderOpenID)
pre_save.connect(signals.set_identityprovider_type, sender=IdentityProviderLocal)
pre_save.connect(signals.set_identityprovider_type, sender=IdentityProviderLDAP)
post_save.connect(signals.add_local_identifier, sender=User)
