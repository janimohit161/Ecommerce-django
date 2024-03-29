from django.shortcuts import render,redirect,get_object_or_404
from . forms import RegistrationForm,UserProfileForm,UserForm
from . models import Account,UserProfile
from orders.models import Order,OrderProduct
from django.contrib import messages,auth
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
# verification email
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage

from carts.views import _cart_id
from carts.models import Cart,CartItem

import requests

def register(request):
    
    if request.method == 'POST':
        form=RegistrationForm(request.POST)
        if form.is_valid():
            first_name=form.cleaned_data['first_name']
            last_name=form.cleaned_data['last_name']
            phone_number=form.cleaned_data['phone_number']
            email=form.cleaned_data['email']
            password=form.cleaned_data['password']
            username=email.split("@")[0]
        
            user=Account.objects.create_user(first_name=first_name, last_name=last_name, email=email,username=username, password=password)
        
            user.phone_number=phone_number
            user.save()
            
            # create user profile
            profile=UserProfile()
            profile.user_id=user.id
            profile.profile_picture='default/default-user.png'
            profile.save()
            
            # user activation
            current_site=get_current_site(request)
            mail_subject="Please activate your account"
            message=render_to_string('accounts/account_verification_email.html',{
                'user': user,
                'domain':current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':default_token_generator.make_token(user),
            })
            
            to_email=email
            send_email=EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            
            
            # messages.success(request, "Thank you for register.We are send you a verification email to your email address.Please Verify it.")
            return redirect('/accounts/login/?command=verification&email='+email)
        
        
    else: 
        form=RegistrationForm()
    
    context={
        'form':form,
    }
    
    return render(request,'accounts/register.html',context)

def login(request):
    if request.method=='POST':
        email=request.POST['email']
        password=request.POST['password']
        
        user=auth.authenticate(email=email,password=password)
        
        if user is not None:
            try:
                cart=Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exists=CartItem.objects.filter(cart=cart).exists()
                if is_cart_item_exists:
                    cart_item=CartItem.objects.filter(cart=cart)
                    
                    # print(cart_item)
                    # give the quary set fotr example <QuerySet [<CartItem: CartItem object (60)>, <CartItem: CartItem object (61)>]>
                    
                    # getting the product variation by cart id
                    product_variation=[]
                    id=[]
                    for item in cart_item:
                        variation=item.variation.all()
                        product_variation.append(list(variation))
                        id.append(item.id)
                    # print(product_variation)
                    # print(id)
                    # [[<Variation: Black>, <Variation: Small>], [<Variation: Black>, <Variation: Medium>]]
                    
                    
                    # get the cart item from the user to access his product variations
                    cart_item=CartItem.objects.filter(user=user)
                    # print(cart_item)
                    # <QuerySet [<CartItem: CartItem object (56)>, <CartItem: CartItem object (57)>, <CartItem: CartItem object (58)>, <CartItem: CartItem object (59)>]>
                    ex_var_list=[]
                    id_existance=[]
                    for item in cart_item:
                        existing_variation=item.variation.all()
                        ex_var_list.append(list(existing_variation))
                        id_existance.append(item.id)
                        
                    # print(ex_var_list)
                    # [[<Variation: Red>, <Variation: Small>], [<Variation: Red>, <Variation: Medium>], [<Variation: Red>, <Variation: Large>], [<Variation: Blue>, <Variation: Small>]]
                    # print(id_existance)
                    # [56, 57, 58, 59]
                                
                                                                
                    item_list=[]
                    for pr in product_variation:
                        if pr in ex_var_list:
                        # increase the cart item quantity
                            
                            index=product_variation.index(pr)
                            item_id=id[index]
                            item=CartItem.objects.get(id=item_id)
                            item_list.append(item)
                            # print(item)
                            
                            index_existance=ex_var_list.index(pr)
                            item_id_existance=id_existance[index_existance]
                            item_existance=CartItem.objects.get(id=item_id_existance)
                            # print(item_existance)
                            
                            item_existance.quantity+=item.quantity
                            item_existance.user=user
                            item_existance.save()
                            item.delete()
                        else: 
                            cart_item=CartItem.objects.filter(cart=cart)
                            # print(cart_item)
                            # <QuerySet [<CartItem: CartItem object (60)>, <CartItem: CartItem object (61)>]>
                            # print(item_list) # which is already in existance list(we add in existance list)
                            for object in cart_item:
                                if object not in item_list:
                                    object.user=user
                                    object.save()
                                else:
                                    pass
                        
            except:          
                pass
            auth.login(request,user)
            messages.success(request,'You are logged in')
            url=request.META.get('HTTP_REFERER')
            try:
                quary=requests.utils.urlparse(url).query
                # print(quary)  --> next=/cart/checkout/
                params=dict(x.split('=')for x in quary.split('&'))
                # print(params)  --> {'next': '/cart/checkout/'}
                if 'next' in params:
                    nextpage=params['next']
                    return redirect(nextpage)
                
            except:
                return redirect('dashboard')
        
        else:
            # messages.error(request,'Invalid Credentials')
            messages.error(request,'You need to activate your account')
            return redirect('login')
    return render(request,'accounts/login.html')


@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    messages.success(request,'You are logged out')
    return redirect('login')
    # return render(request,'accounts/logout.html')
    
    
def activate(request,uidb64,token):
    try:
        uid=urlsafe_base64_decode(uidb64).decode()
        user=Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user=None
    
    if user is not None and default_token_generator.check_token(user,token):
        user.is_active=True
        user.save()
        messages.success(request,"Congratulations! Your account is activated.")
        return redirect('login')
    else:
        messages.error(request,'Invalid activation link')
        return redirect('register')
    

@login_required(login_url='login')
def dashboard(request):
    orders=Order.objects.order_by('-created_at').filter(user_id=request.user.id,is_ordered=True)
    orders_count=orders.count()
    userprofile=UserProfile.objects.get(user_id=request.user.id)
    context={
        'orders_count':orders_count,
        'userprofile':userprofile,
    }
    return render(request,'accounts/dashboard.html',context)


def forgotPassword(request):
    if request.method == 'POST':
        email=request.POST['email']
        if Account.objects.filter(email=email).exists():
            user=Account.objects.get(email__exact=email)
            
            # Reset password email
            current_site=get_current_site(request)
            mail_subject="Reset your Password"
            message=render_to_string('accounts/reset_password_email.html',{
                'user': user,
                'domain':current_site,
                'uid':urlsafe_base64_encode(force_bytes(user.pk)),
                'token':default_token_generator.make_token(user),
            })
            
            to_email=email
            send_email=EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()
            
            messages.success(request,"Password reset email has been sent to your email address.")
            return redirect('login')
        else:
            messages.error(request,"Account does not exist")
            return redirect('forgotPassword')
             
    return render(request,'accounts/forgotPassword.html')


def resetpassword_validate(request,uidb64,token):
    try:
        uid=urlsafe_base64_decode(uidb64).decode()
        user=Account._default_manager.get(pk=uid)
    except(TypeError,ValueError,OverflowError,Account.DoesNotExist):
        user=None
        
    if user is not None and default_token_generator.check_token(user,token):
        request.session['uid']=uid
        messages.success(request,'Please reset your password')
        return redirect('resetPassword')
        
    else:
        messages.error(request,'This link has been expired!')
        return redirect('login')
    
    
def resetPassword(request):
    if request.method == 'POST':
        password=request.POST['password']
        confirm_password=request.POST['confirm_password']
        
        if password == confirm_password:
            uid=request.session.get('uid')
            user=Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request,'Password reset successful')
            return redirect('login')
            
        else:
            messages.error(request,'Password do not match')
            return redirect('resetPassword')
    else:
        return render(request,'accounts/resetPassword.html')
    
    
@login_required(login_url='login')
def my_orders(request):
    orders=Order.objects.filter(user=request.user,is_ordered=True).order_by('-created_at')
    context={
        'orders': orders,
    }
    return render(request, 'accounts/my_orders.html',context)



@login_required(login_url='login')
def edit_profile(request):
    userprofile=get_object_or_404(UserProfile,user=request.user)
    if request.method == 'POST':
        user_form=UserForm(request.POST,instance=request.user)
        profile_form=UserProfileForm(request.POST,request.FILES,instance=userprofile)
        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request,'Your profile has been Updated.')
            return redirect('edit_profile')
    else:
        user_form=UserForm(instance=request.user)
        profile_form=UserProfileForm(instance=userprofile)
        
    context={
        'user_form': user_form,
        'profile_form': profile_form,
        'userprofile': userprofile,
    }
    return render(request,'accounts/edit_profile.html',context)



@login_required(login_url='login')
def change_password(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']
        
        user=Account.objects.get(username__exact=request.user.username)
        
        if new_password == confirm_password:
            success=user.check_password(current_password)
            if success:
                user.set_password(new_password)
                user.save()
                # auth logout(request)  if we want logout user
                messages.success(request,'password change suceesfully')
                return redirect('change_password')
            else:
                messages.error(request,'Please enter valid current password')
                return redirect('change_password')
        else:
            messages.error(request,'Password does not match')
            return redirect('change_password')
    return render(request,'accounts/change_password.html')



@login_required(login_url='login')
def order_detail(request,order_id):
    order_detail = OrderProduct.objects.filter(order__order_number=order_id)
    order=Order.objects.get(order_number=order_id)
    subtotal=0
    for i in order_detail:
        subtotal += i.product_price * i.quantity
    context={
        'order_detail':order_detail,
        'order':order,
        'subtotal':subtotal,
    }
    return render(request,'accounts/order_detail.html',context)