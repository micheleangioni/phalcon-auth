# Phalcon Auth

[![License](https://poser.pugx.org/michele-angioni/phalcon-auth/license)](https://packagist.org/packages/michele-angioni/phalcon-auth)
[![Latest Stable Version](https://poser.pugx.org/michele-angioni/phalcon-auth/v/stable)](https://packagist.org/packages/michele-angioni/phalcon-auth)
[![Latest Unstable Version](https://poser.pugx.org/michele-angioni/phalcon-auth/v/unstable)](https://packagist.org/packages/michele-angioni/phalcon-auth)
[![Build Status](https://travis-ci.org/micheleangioni/phalcon-auth.svg)](https://travis-ci.org/micheleangioni/phalcon-auth)

## Introduction

Phalcon Auth provides you a fast way to register and authenticate your users. 

Every application, every website needs its own User model with its own properties and methods. 
Phalcon Auth does not force you to use its own model nor create useless overhead by defining relationships with other models. 
You are a Phalcon user, so speed and simplicity is what you are looking for.

So, Phalcon Auth just requires your own User model to satisfy some requirements by implementing its interface. 
Basically, it just need a few methods: 

- getId() : (int)
- getEmail() : (string)
- getPassword() : (string)
- setPassword($password) : (bool)
- getConfirmationCode() : (string)
- setConfirmationCode($confirmationCode) : (bool)
- confirm() : (bool) 
- isConfirmed() : (bool)
- isBanned() : (bool)

Furthermore, if you want to use the "remember me" feature, the following remember token getter and setter are required
 
 - getRememberToken()  : (string)
 - setRememberToken($token) : (bool)

## Installation
 
Support can be installed through Composer, just include `"michele-angioni/phalcon-auth": "~0.1"` to your composer.json and run `composer update` or `composer install`.

## Usage

Let's say you have a `MyApp\Users` model you want to make authenticatable.
The way to do it is very simple, i.e. it must implement the `MicheleAngioni\PhalconAuth\Contracts\AuthableInterface` or, if you want to use the remember me feature, the `MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface`.

An example can be the this one:

    namespace MyApp;

    class Users extends \Phalcon\Mvc\Model implements \MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface
    {
        protected $id;
        
        protected $banned;
    
        protected $confirmation_code;
    
        protected $confirmed;
    
        protected $email;
    
        protected $password;
    
        protected $remember_token;
    
        public function getId()
        {
            return $this->id;
        }
    
        public function getConfirmationCode()
        {
            return $this->confirmation_code;
        }
    
        public function isConfirmed()
        {
            return (bool)$this->confirmed;
        }
    
        public function getEmail()
        {
            return $this->email;
        }
        
        public function setEmail($email)
        {
            $this->email = $email;
            return true;
        }
    
        public function getPassword()
        {
            return $this->password;
        }
        
        public function setPassword($password)
        {
            $this->password = $password;
            return true;
        }
    
        public function getRememberToken()
        {
            return $this->remember_token;
        }
    
        public function setRememberToken($token)
        {
            $this->remember_token = $token;
            return true;
        }
        
        public function isBanned()
        {
            return (bool)$this->banned;
        }
    }

We can then define the `auth` service in the Phalcon container in application bootstrap file, and pass the `MyApp\Users` model to it.
This way, it will be easily retrievable for example in the controllers

    /**
     * Authentication
     */
    $di->setShared('auth', function () {
        return \MicheleAngioni\PhalconAuthAuth(new \MyApp\Users());
    });

Now we can define a simple controller for User registration, confirmation, login, logout and password reset:

    <?php
    
    namespace MyApp\Controllers;
    
    use Phalcon\Mvc\Controller;
    
    class AuthController extends Controller
    {

        public function registerAction()
        {
            $email = $this->request->getPost('email);
            $password = $this->request->getPost('password);
            
            // [..] Data validation
        
            // Retrieve Auth Service
            $auth = $this->getDI()->get('auth');
            
            // Register the new user
            
            try {
                $user = $auth->register($email, $password);
            } catch (\Exception $e) {
                if ($e instanceof \UnexpectedValueException) {
                    // The email has already been taken, handle the exception
                } else {
                    // Handle other exception
                }
            }
    
            [...] // It is up to you to comunicate the confirmation code to the user
        }
        
        public function confirmAction($idUser, $confirmationCode)
        {
            // Retrieve Auth Service
            $auth = $this->getDI()->get('auth');
            
            // Confirm the user
            
            try {
                $user = $auth->confirm($idUser, $confirmationCode);
            } catch (\Exception $e) {
                if ($e instanceof \EntityNotFoundException) {
                    // User not found. Handle the exception
                } else {
                    // Wrong confirmation code. Handle other exception
                }
            }
    
            [...]
        }
        
        public function loginAction()
        {
            $email = $this->request->getPost('email);
            $password = $this->request->getPost('password);
            
            // [..] Data validation
        
            // Retrieve Auth Service
            $auth = $this->getDI()->get('auth');
            
            // Perform login
            
            try {
                $user = $auth->attemptLogin($email, $password);
            } catch (\Exception $e) {
                if ($e instanceof \MicheleAngioni\PhalconAuth\Exceptions\EntityBannedException) {
                    // The user is banned. Handle exception
                } else {
                    // Handle wrong credentials exception
                }
            }
    
            [...]
        }
        
        public function logoutAction()
        {
            // Retrieve Auth Service
            $auth = $this->getDI()->get('auth');
            
            // Perform logout
            $auth->logout();
    
            [...]
        }
        
        public function getPasswordTokenAction($idUser)
        {
            // Retrieve Auth Service
            $auth = $this->getDI()->get('auth');
            
            // Get the reset password token
            
            try {
                $token = $auth->getResetPasswordToken($idUser);
            } catch (\Exception $e) {
                if ($e instanceof \MicheleAngioni\PhalconAuth\Exceptions\EntityNotFoundException) {
                    // User not found. Handle the exception
                } else {
                    // Authable entity is not confirmed yet, it cannot reset the password. Handle the exception
                }
            }
    
            [...]
        }
        
        public function resetPasswordAction($idUser, $resetToken)
        {
            $password = $this->request->getPost('newPassword);
                        
            // [..] Data validation
        
            // Retrieve Auth Service
            $auth = $this->getDI()->get('auth');
            
            // Get the reset password token
            
            try {
                $token = $auth->resetPassword($idUser, $resetToken, $newPassword);
            } catch (\Exception $e) {
                if ($e instanceof \MicheleAngioni\PhalconAuth\Exceptions\EntityNotFoundException) {
                    // User not found. Handle the exception
                } else {
                    // Authable entity is not confirmed or the token is wrong. Handle the exception
                }
            }
    
            [...]
        }
    }

After the login, the user id and email will be saved in the session. 

### Advanced user registration

When registering a new user, you can pass an array of other parameters and an array of parameters you want to be unique in your user table

    $auth->register($email, $password, $parameters = [], $uniqueParameters = [], $addConfirmationCode = true));
   
### Customize login

You can customize the login settings by modifying the other method parameters

    $auth->attemptLogin($email, $password, $saveSession = true, $rememberMe = false);
    
### Logging in after the "remember me" has been set

After authenticating with a "remember me", just use the following method

    if ($auth->hasRememberMe()) {
        $auth->loginWithRememberMe();
    }

### Retrieve the logged user info from the session

    $auth->getIdentity(); // Returns an array with 'id' and 'email' keys
    
### Retrieve the authenticated user

    $auth->getAuth();
    
### Manually login through user id

    $auth->authById($id);

### Customize the behaviour
    
When defining the Auth service, you can can pass an options array. Below all available options are listed

        /**
         * Authentication
         */
         $options = [
            'rememberMeDuration' => 1096000 // Optional, default: 604800 (1 week)
         ];
         
        $di->set('auth', function () {
            return \MicheleAngioni\PhalconAuthAuth(new \MyApp\Users(), $options);
        });
    
## Contribution guidelines

Phalcon Auth follows PSR-1, PSR-2 and PSR-4 PHP coding standards, and semantic versioning.

Pull requests are welcome.

## License

Phalcon Auth is free software distributed under the terms of the MIT license.
