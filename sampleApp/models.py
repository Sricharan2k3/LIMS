from django.db import models
import uuid

from django.contrib.auth.models import AbstractUser

from django.core.validators import MaxValueValidator, MinValueValidator

# Create your models here.


class Category(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    name = models.CharField(max_length=200)
    cover_image = models.ImageField(upload_to='categories/')

    def __str__(self):
        return self.name


class Book(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True)
    title = models.CharField(max_length=200)
    description = models.TextField()
    cover_image = models.ImageField(upload_to='covers/')
    categories = models.ManyToManyField(Category)
    author = models.CharField(max_length=20)
    availability = models.IntegerField(default=0)
    language = models.CharField(max_length=20)
    isbn = models.CharField(max_length=50)
    year = models.IntegerField(blank=True, validators=[
                               MinValueValidator(1800), MaxValueValidator(2023)])

    def __str__(self):
        return self.title


class User(AbstractUser):
    # Add custom fields here if needed
    username = models.CharField(
        max_length=150,
        unique=True,
        default='default_username'
    )

    user_permissions = models.ManyToManyField(
        'auth.Permission',
        verbose_name='user permissions',
        blank=True,
        related_name='custom_user_set'
    )

    groups = models.ManyToManyField(
        'auth.Group',
        verbose_name='user groups',
        blank=True,
        related_name='custom_user_set'
    )

    email = models.EmailField(unique=True)

    profile_image = models.ImageField(
        upload_to='covers/profile', default='covers/profile/user.png')


class BookIssue(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    book = models.ForeignKey(Book, on_delete=models.CASCADE)
    issued_at = models.DateTimeField(auto_now_add=True)
    returned_at = models.DateTimeField(null=True, blank=True)
