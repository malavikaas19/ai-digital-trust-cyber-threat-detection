
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm

from .models import UserProfile


# USER REGISTRATION FORM
class RegisterForm(UserCreationForm):

    first_name = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter your full name'
        })
    )

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'placeholder': 'Enter your email'
        })
    )

    class Meta:
        model = User
        fields = [
            'first_name',
            'username',
            'email',
            'password1',
            'password2'
        ]


# USER PROFILE UPDATE FORM
class ProfileUpdateForm(forms.ModelForm):

    first_name = forms.CharField(
        max_length=150,
        required=True
    )

    email = forms.EmailField(
        required=True
    )

    class Meta:
        model = UserProfile
        fields = ['profile_image']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

        self.fields['first_name'].initial = self.user.first_name
        self.fields['email'].initial = self.user.email

    def save(self, commit=True):
        profile = super().save(commit=False)

        self.user.first_name = self.cleaned_data['first_name']
        self.user.email = self.cleaned_data['email']

        if commit:
            self.user.save()
            profile.user = self.user
            profile.save()

        return profile
