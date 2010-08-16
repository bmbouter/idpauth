from django.shortcuts import render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.template import RequestContext
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.sites.models import Site
from django.core.urlresolvers import reverse

from idpauth.models import IdentityProvider, IdentityProviderLDAP, UserProfile
from idpauth import openid_tools
from idpauth import authentication_tools
from idpauth import ldap_tools
from idpauth.forms import UserCreationForm, AuthenticationForm

from opus.lib import log
log = log.getLogger()


def determine_login(request, message=None, template_name=None, redirect_url=None, redirect_viewname=None):
    if "next" in request.GET:
        next = request.GET['next']
    elif not redirect_url:
        if redirect_viewname != None:
            next = reverse(redirect_viewname)
        else:
            next = settings.RESOURCE_REDIRECT_URL
    else:
        next = redirect_url

    if not template_name:
        institution = authentication_tools.get_institution(request)
        institutional_idp = IdentityProvider.objects.filter(institution__iexact=str(institution))

        if not institutional_idp:
            log.debug("No institution")
            return HttpResponse("There is no Identity Provider specified for your institution")
        else:
            authentication_type = institutional_idp[0].type
            template_name = 'idpauth/' + str(authentication_type) + '.html'
            if authentication_type == 'local':
                return HttpResponseRedirect(reverse("local_login_url",
                    kwargs={ 'template_name' : template_name,
                            'redirect_url' : next,  }))
        
    return render_to_response(template_name,
        {'next': next,
        'message' : message, },
        context_instance=RequestContext(request))


def ldap_login(request):
    username = request.POST['username']
    password = request.POST['password']
    resource_redirect_url = request.POST['next']

    institution = authentication_tools.get_institution(request)
    identityprovider = IdentityProviderLDAP.objects.filter(institution__iexact=str(institution))
    if identityprovider:
        server = identityprovider[0]
        roles = ldap_tools.get_ldap_roles(server, username, password)

        username = institution + "++" + username
        user = authenticate(username=username)
        roles = str(roles).strip('[').strip(']')
        try:
            user_profile = user.get_profile()
            user_profile.ldap_roles = roles
            user_profile.save()
        except ObjectDoesNotExist:
            user_profile = UserProfile(user=user, ldap_roles=roles)
            user_profile.save()

        if user is not None:
            if roles == None:
                log.debug("Roles were none, redirecting to login")
                return HttpResponseRedirect(settings.LOGIN_URL)
            else:
                log.debug("Logging user in")
                login(request, user)
                authentication_tools.add_session_username(request, username)
                log.debug("Redirecting to " + resource_redirect_url)
                return HttpResponseRedirect(resource_redirect_url)
        else:
            log.debug("No user found")
            return HttpResponseRedirect(settings.LOGIN_URL)
    else:
        message = 'There were errors retrieving the identity provider'
        return render_to_response('idpauth/ldap.html', 
        {'next' : resource_redirect_url,
        'message' : message},
        context_instance=RequestContext(request))


def openid_login(request, redirect_to=None):
    openid_url = request.POST['openid_url']
    resource_redirect_url = request.POST['next']
    log.debug(resource_redirect_url)
    institution = authentication_tools.get_institution(request)
    session = request.session

    trust_root = authentication_tools.get_url_host(request)
    if not redirect_to:
        redirect_url = openid_tools.begin_openid(session, trust_root, openid_url, resource_redirect_url)
    else:
        log.debug(redirect_to)
        redirect_url = openid_tools.begin_openid(session, trust_root, openid_url, resource_redirect_url, redirect_to)

    if not redirect_url:
        return HttpResponse('The OpenID was invalid')
    else:
        return HttpResponseRedirect(redirect_url)


def openid_login_complete(request):
    institution = authentication_tools.get_institution(request)
    resource_redirect_url = request.GET['next']
    session = request.session
    
    host = authentication_tools.get_url_host(request)
    nonce = request.GET['janrain_nonce']
    if not "" == settings.OPENID_COMPLETE_URL:
        url = openid_tools.get_return_url(host, nonce, settings.OPENID_COMPLETE_URL)
    else:
        url = openid_tools.get_return_url(host, nonce)
    
    query_dict = dict([
        (k.encode('utf8'), v.encode('utf8')) for k, v in request.GET.items()])
    
    status, username = openid_tools.complete_openid(session, query_dict, url)

    if status == "SUCCESS":
        username = username
        user = authenticate(username=username)
        if user is not None:
            if user.is_active:
                log.debug("Logging user in")
                login(request, user)
                authentication_tools.add_session_username(request, username.split('@')[0])
                log.debug("Redirecting to " + resource_redirect_url)
                return HttpResponseRedirect(resource_redirect_url)
            else:
                log.debug("User is no longer active")
                return HttpResponseRedirect(settings.LOGIN_URL)   
        else:
            log.debug("No user found")
            return HttpResponseRedirect(settings.LOGIN_URL)   
        
    elif status == "CANCEL":
        message = "OpenID login failed due to a cancelled request.  This can be due to failure to release email address which is required by the service."
        return render_to_response('idpauth/openid.html',
        {'message' : message,
        'next' : resource_redirect_url,},
        context_instance=RequestContext(request))
    elif status == "FAILURE":
        return render_to_response('idpauth/openid.html',
        {'message' : username,
        'next' : resource_redirect_url,},
        context_instance=RequestContext(request))

    else:
        message = "An error was encountered"
        return render_to_response('idpauth/openid.html',
        {'message' : message,
        'next' : resource_redirect_url, },
        context_instance=RequestContext(request))


def local_login(request, template_name=None, redirect_url=None, redirect_viewname=None):
    message = None
    if "next" in request.REQUEST:
        next = request.REQUEST['next']
    elif not redirect_url:
        if redirect_viewname != None:
            next = reverse(redirect_viewname)
        else:
            next = settings.RESOURCE_REDIRECT_URL
    else:
        next = redirect_url

    if request.method == 'POST':
        form = AuthenticationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            username = "local++" + username
            user = authenticate(username=username, password=password)
            log.debug("Auhentication")
            if user is not None:
                login(request, user)
                log.debug("Login")
                institution = authentication_tools.get_institution(request)
                authentication_tools.add_session_username(request, username)
                return HttpResponseRedirect(next)
            else:
                message = "Invalid username or password"
                form = AuthenticationForm()
    else:
        form = AuthenticationForm()
    return render_to_response(template_name,
            { 'form' : form,
            'next' : next,
            'message' : message, },
            context_instance=RequestContext(request))


def shibboleth_login(request):
    try:
        username = request.META['REMOTE_USER']
        user_tools.login(request, username, "T", "null")
        
        return HttpResponse("Remote user set to:  " + remote_user)
    except KeyError, e:
        log.debug(e)
        return HttpResponse("Remote user not set.")


def user_registration(request, template_name=None, redirect_url=None):
    if "next" in request.REQUEST:
        next = request.REQUEST['next']
        log.debug("Setting next " + next)
    elif not redirect_url:
        next = settings.RESOURCE_REDIRECT_URL
    else:
        next = redirect_url

    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            log.debug("Redirecting to: " + next)
            return HttpResponseRedirect(next)
    else:
        form = UserCreationForm()
    return render_to_response(template_name,
            { 'form' : form,
            'next' : next, },
            context_instance=RequestContext(request))


@login_required
def logout_view(request, template_name=None, redirect_url=None, redirect_viewname=None):
    try:
        del request.session['username']
    except KeyError:
        pass
    logout(request)
    #institution = authentication_tools.get_institution(request)
    
    if not template_name:
        template_name = 'idpauth/logout.html'

    if "next" in request.GET:
            next = request.GET['next']
    elif not redirect_url:
        if redirect_viewname != None:
            next = reverse(redirect_viewname)
        else:
            next = None
    else:
        next = redirect_url

    return render_to_response(template_name,
            {'next' : next, },
            context_instance=RequestContext(request))
