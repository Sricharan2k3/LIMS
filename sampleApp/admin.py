from django.contrib import admin
from .models import Book,User,Category,BookIssue

# Register your models here.
admin.site.register(Book)
admin.site.register(User)
admin.site.register(Category)
admin.site.register(BookIssue)