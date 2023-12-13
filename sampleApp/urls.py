
from django.urls import path
from . import views


urlpatterns = [
    path('', views.index, name="index"),
    path('add_book', views.add_book, name="add_book"),
    path('login', views.login, name="login"),
    path('register', views.register, name="register"),
    path('update/<int:book_id>', views.update, name='update'),

    path('view_book', views.view_book, name="view_book"),
    path('category/<str:categoryid>', views.category, name="category"),
    path('profile', views.profile, name="profile"),
    path('logout', views.logout, name="logout"),
    path('update1/<str:book_id>/<int:user_id>/', views.update1, name='update1'),
    path('book/<str:book_id>', views.view_book, name='temp'),
    path('get_otp', views.get_otp, name='generate_otp'),





]
