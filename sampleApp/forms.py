from django import forms
from .models import Book
from .models import User


class BookForm(forms.ModelForm):
    class Meta:
        model = Book
        fields = '__all__'


class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    email = forms.EmailField(widget=forms.EmailInput)
    profile_image = forms.ImageField(widget=forms.ClearableFileInput)

    class Meta:
        model = User
        fields = ('username', 'password', 'email', 'profile_image')


class LoginForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
