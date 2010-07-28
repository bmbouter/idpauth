from django import forms
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.models import User

from idpauth.models import IdentityProvider

from opus.lib import log
log = log.getLogger()

class IdpAdminForm(forms.ModelForm):
    class Meta:
        model = IdentityProvider

    def clean_institution(self):
        if not self.cleaned_data["institution"].islower():
            institution_lowered = self.cleaned_data["institution"].lower()
            try:
                IdentityProvider.objects.get(institution__iexact=institution_lowered)
                raise forms.ValidationError("Institution \"%s\" exists already" 
                                            % self.cleaned_data["institution"].lower())
            except ObjectDoesNotExist:
                pass
        return self.cleaned_data["institution"].lower()


class UserCreationForm(forms.ModelForm):
    username = forms.RegexField(label=("Username"), max_length=30, regex=r'^[\w.@+-]+$',
    error_messages = {'invalid': ("This value may contain only letters, numbers and @/./+/-/_ characters.")})
    password1 = forms.CharField(label=("Password"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=("Password confirmation"), widget=forms.PasswordInput)
    #email = forms.EmailField(label="Email")
    help_text = ("Enter the same password as above, for verification.")
    
    class Meta:
        model = User
        fields = ("username", "email",)
        
    def clean_username(self):
        username = self.cleaned_data["username"]
        try:
            User.objects.get(username=username)
        except User.DoesNotExist:
            return username
        raise forms.ValidationError("A user with that username already exists.")
         
    def clean_password2(self):
        password1 = self.cleaned_data.get("password1", "")
        password2 = self.cleaned_data["password2"]
        if password1 != password2:
             raise forms.ValidationError("The two password fields didn't match.")
        return password2
              
    def save(self, commit=True):
        user = super(UserCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
