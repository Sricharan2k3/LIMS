from django.shortcuts import render, redirect
from django.http import HttpResponse
from .models import Book, User, Category
from .forms import BookForm, LoginForm, RegistrationForm
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from .models import BookIssue
from datetime import timedelta
from datetime import date
import pytz
from django.utils import timezone
import random
from django.core.mail import send_mail
from django.core.mail import send_mail
from django.shortcuts import redirect
from django_otp.oath import TOTP
import pyotp
from django.conf import settings


from django.contrib.auth.hashers import check_password


def change_password(request):
    if request.method == 'POST':
        current_pass = request.POST.get('current_pass')
        new_pass = request.POST.get('new_pass')
        password_match = check_password(current_pass, request.user.password)
        if password_match:
            print("Current password matched")
            return redirect('profile')
        else:
            return redirect('profile')


def generate_totp():
    # Generate a random secret key (make sure to store this securely for each user)
    secret_key = pyotp.random_base32()

    # Convert the secret_key to bytes
    secret_key_bytes = secret_key.encode()

    # Create a TOTP object with the given secret key as bytes
    totp = TOTP(secret_key_bytes)

    # Get the current OTP based on the current time
    otp = totp.token()

    return secret_key, otp


def get_otp(request):
    if request.method == 'POST':
        otp = request.session.get('otp', None)
        # Clean the user-entered OTP
        user_entered_otp = int(request.POST.get('otp'))

        if otp is None:
            return redirect('login')

        if otp == user_entered_otp:

            del request.session['otp']
            request.session.save()
            return redirect('index')
        else:
            messages.error(
                request, 'Invalid OTP. Please try again.')

            return render(request, 'otp.html')

    return redirect('login')


def update1(request, book_id, user_id):
    print("h5")
    book = get_object_or_404(Book, pk=book_id)
    user = get_object_or_404(User, pk=user_id)
    issued_at = timezone.now().astimezone(pytz.timezone('Asia/Kolkata'))
    returned_at = issued_at + timedelta(days=30)

    # Check if the book is available
    if book.availability > 0:
        # Calculate the issue and return dates in Indian Standard Time (IST)
        tz = pytz.timezone('Asia/Kolkata')
        issued_at = timezone.now().astimezone(tz)
        returned_at = issued_at + timedelta(days=30)

        # Create a new BookIssue record and set the issued_at and returned_at timestamps
        issue = BookIssue(user=user, book=book,
                          issued_at=issued_at, returned_at=returned_at)
        issue.save()

        # Update the availability of the book and save it
        book.availability -= 1
        book.save()

        # Get all issued books for rendering in the template
        issued_books = BookIssue.objects.select_related('book', 'user').all()

        # Get the referring URL (current page)
        referring_url = request.META.get('HTTP_REFERER', '/')

        # Redirect the user back to the current page with the updated issued books list

        return redirect('/book/'+book_id)
    else:
        # Book is not available, handle this case as needed (e.g., show an error message)
        print("No books available")
        # You can also pass an error message to the template if you wish:
        return redirect('/book/'+book_id)


def index(request):
    users = User.objects.all()
    books = Book.objects.all()  # Fetch all book objects from the database
    categories = Category.objects.all()
    booksrand = []
    for i in range(5):
        rand = random.choice(books)
        while (rand in booksrand):
            rand = random.choice(books)
        booksrand.append(rand)

    dict = {}
    for user in users:
        issued_books = BookIssue.objects.select_related(
            'book').filter(user=user).count()
        print(issued_books)
        dict[user.id] = issued_books

    sorted_list = [key for key, value in sorted(
        dict.items(), key=lambda x: x[1], reverse=True)]

    # top_users=User.objects.filter(id__in=sorted_list[0:3])
    top_users = User.objects.filter(id__in=sorted_list[0:3])
    print(top_users)

    return render(request, 'index.html', {'books': booksrand, 'all_categories': categories[4:], 'categories': categories[0:4], 'top_users': top_users})


def login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)

        if form.is_valid():

            email = form.cleaned_data['email']

            password = form.cleaned_data['password']
            remember_me = request.POST.get('remember_me')
            user = authenticate(request, email=email, password=password)
            if user is not None:
                auth_login(request, user)
                if remember_me:

                    request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                else:

                    request.session.set_expiry(0)

                secret_key, otp = generate_totp()
                print(secret_key)

                subject = 'Your OTP for Login'
                message = f'Your One-Time Password (OTP) is: {otp}'

                from_email = 'namasricharan@gmail.com'
                recipient_list = [email]

                send_mail(subject, message, from_email, recipient_list)
                request.session['otp'] = otp
                request.session['secret_key'] = secret_key
                request.session.save()

                return render(request, 'otp.html')

            else:
                messages.error(
                    request, 'Invalid credentials. Please try again.')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


# def get_otp(request):

#     otp = request.session.get('otp', None)
#     secret_key = request.session.get('secret_key', None)
#     print(secret_key)
#     user_entered_otp = request.POST.get('otp')
#     print(otp)
#     print(user_entered_otp)

#     # Make sure both the OTP and secret_key are present in the session
#     if otp is None or secret_key is None:
#         # Handle the case where OTP or secret_key is missing.
#         # For example, redirect back to the login page with an error message.
#         return redirect('login')

#     if otp==user_entered_otp:
#             return redirect('index')

#     del request.session['otp']
#     del request.session['secret_key']
#     request.session.save()

    # Now you have the OTP and secret_key available to use in this view
    # ... (perform your desired actions with the OTP and secret_key)

    # Optionally, remove the OTP and secret_key from the session after using them

    # if request.method=='POST':

    #     user_entered_otp = request.POST.get('otp')
    #     print(user_entered_otp)

    #     otp = request.session.get('otp', None)

    #     if otp is None:

    #         return redirect('login')  # Replace 'login' with your login page URL

    #     if otp==user_entered_otp:
    #         return redirect('index')

    #     else:
    #         return redirect('login')

    # Now you can use the OTP as needed in the `another_view` function
    # ...

    # Make sure to remove the OTP from the session after using it (optional)
    # del request.session['otp']
    # request.session.save()

    # if request.method == 'GET':
    #     email = request.GET.get('email', None)

    #     if email:
    #         # Generate the OTP here (You can use the same code to generate the OTP as before)
    #         otp = '123456'  # Replace this with your OTP generation logic

    #         subject = 'Your OTP for Login'
    #         message = f'Your One-Time Password (OTP) is: {otp}'
    #         from_email = 'namasricharan@gmail.com'  # Replace with your email sending address.
    #         recipient_list = [email]

    #         try:
    #             # Send the email
    #             send_mail(subject, message, from_email, recipient_list)

    #             # Return a success response indicating the OTP has been sent
    #             return JsonResponse({'status': 'success', 'message': 'OTP sent successfully'})
    #         except Exception as e:
    #             # Return an error response if there was an issue sending the email
    #             return JsonResponse({'status': 'error', 'message': f'Failed to send OTP. Error: {e}'})
    #     else:
    #         # Return an error response if email is not provided
    #         return JsonResponse({'status': 'error', 'message': 'Email not provided'})

    # # Return an error response if the request method is not GET
    # return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def update(request, book_id):
    if request.user.is_authenticated:
        print("h5")
        user_id = request.user.id
        book = get_object_or_404(Book, pk=book_id)
        user = get_object_or_404(User, pk=user_id)
        issued_at = timezone.now().astimezone(pytz.timezone('Asia/Kolkata'))
        returned_at = issued_at + timedelta(days=30)

        # Check if the book is available
        if book.availability > 0:
            # Calculate the issue and return dates in Indian Standard Time (IST)
            tz = pytz.timezone('Asia/Kolkata')
            issued_at = timezone.now().astimezone(tz)
            returned_at = issued_at + timedelta(days=30)

            # Create a new BookIssue record and set the issued_at and returned_at timestamps
            issue = BookIssue(user=user, book=book,
                              issued_at=issued_at, returned_at=returned_at)
            issue.save()

            # Update the availability of the book and save it
            book.availability -= 1
            book.save()

            # Get all issued books for rendering in the template
            issued_books = BookIssue.objects.select_related(
                'book', 'user').all()

            # Get the referring URL (current page)
            referring_url = request.META.get('HTTP_REFERER', '/')

            # Redirect the user back to the current page with the updated issued books list

            return redirect('/book/'+book_id)
        else:
            # Book is not available, handle this case as needed (e.g., show an error message)
            print("No books available")
            # You can also pass an error message to the template if you wish:
            return redirect('/book/'+book_id)
    else:
        return redirect('/')


def index(request):
    users = User.objects.all()
    books = Book.objects.all()  # Fetch all book objects from the database
    categories = Category.objects.all()
    booksrand = []
    for i in range(5):
        rand = random.choice(books)
        while (rand in booksrand):
            rand = random.choice(books)
        booksrand.append(rand)

    dict = {}
    for user in users:
        issued_books = BookIssue.objects.select_related(
            'book').filter(user=user).count()
        print(issued_books)
        dict[user.id] = issued_books

    sorted_list = [key for key, value in sorted(
        dict.items(), key=lambda x: x[1], reverse=True)]

    top_users = User.objects.filter(id__in=sorted_list[0:3])
    print(top_users)

    return render(request, 'index.html', {'books': booksrand, 'all_categories': categories[4:], 'categories': categories[0:4], 'top_users': top_users})


def add_book(request):
    if request.user.is_authenticated:
        if request.user.is_superuser:
            if request.method == 'POST':
                form = BookForm(request.POST, request.FILES)
                print("wow")
                if form.is_valid():
                    form.save()
                    print("hi")
                    print(form.fields["id"])
                    # Replace 'book_list' with the name of your view to display the book list.
                    return redirect('index')
            else:
                print("bye")
                form = BookForm()

            return render(request, 'add_book.html', {'form': form})
        else:
            return redirect('/')
    else:
        return redirect('/')


def register(request):
    if request.user.is_authenticated:
        return redirect('/')
    else:
        if request.method == 'POST':
            print("h2")
            form = RegistrationForm(request.POST, request.FILES)
            print("h3")
            print(form.errors)
            if form.is_valid():
                print("h1")
                user = form.save(commit=False)
                user.set_password(form.cleaned_data['password'])
                email = form.cleaned_data['email']
                user.email = email
                user.save()
                return redirect('login')
        else:
            form = RegistrationForm()
        return render(request, 'register.html', {'form': form})


def view_book(request, book_id):
    if request.user.is_authenticated:
        book = Book.objects.get(pk=book_id)
        user_id = request.user.id
        user = User.objects.get(pk=user_id)
        issued_books = BookIssue.objects.filter(user=user, book=book).count()
        print(issued_books)

        # You can pass the `book` object to the template or perform any other actions as needed

        return render(request, 'book.html', {'book': book, 'issued_books': issued_books, 'count': issued_books})
    else:
        return redirect('login')


def profile(request):
    if request.user.is_authenticated:

        user = request.user
        issued_books = BookIssue.objects.select_related(
            'book').filter(user=user)
        all_books = BookIssue.objects.select_related('book')
        all_users = User.objects.all()
        return render(request, 'profile.html', {'user': user, 'all_users': all_users, 'issued_books': issued_books, 'all_books': all_books})

    else:
        return redirect('login')


def category(request, categoryid):
    category = Category.objects.get(id=categoryid)
    books = Book.objects.filter(categories=category)
    return render(request, 'books.html', {'books': books, 'category': category})


def logout(request):
    auth_logout(request)
    return redirect('login')
