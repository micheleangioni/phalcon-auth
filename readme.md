# Phalcon Auth

## Introduction

Phalcon Auth provides you a fast way to register and authenticate your users. 

Every application, every website needs its own User model with its own properties and methods. 
Phalcon Auth does not force you to use its own model nor create useless overhead by defining relationships with other models. 
You are a Phalcon user, so speed and simplicity is what you are looking for.

So, Phalcon Auth just requires your own User model to satisfy some requirements by implementing its interface. 
Basically, it just need a few property getters: 

- id 
- email
- password
- confirmation_code
- confirmed

Futhermore, if you want to use the "remember me" feature, the remember_token getter and setter are required. 

You can then use Phalcon Auth as provided out of the box or customize its behaviour. Just see below.

## Installation
 
Support can be installed through Composer, just include `"michele-angioni/phalcon-auth": "dev-master"` to your composer.json and run `composer update` or `composer install`.

## Usage

Let's say you have a `MyApp\Users` model you want to make authenticatable.
The way to do it is very simple, i.e. it must implement the `MicheleAngioni\PhalconAuth\Contracts\AuthableInterface` or, if you want to use the remember me feature, the `MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface`.

An example can be the this one:

    namespace MyApp;

    class Users extends \Phalcon\Mvc\Model implements \MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface
    {
        protected $id;
    
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
    
        public function getPassword()
        {
            return $this->password;
        }
    
        public function getRememberToken()
        {
            return $this->remember_token;
        }
    
        public function setRememberToken($token)
        {
            $this->remember_token = $token;
            $this->save();
        }
    }

We can then define the `auth` service in the Phalcon container in application bootstrap file, and pass the `MyApp\Users` model to it.
This way, it will be easily retrievable for example in the controllers

    /**
     * Authentication
     */
    $di->set('auth', function () {
        return \MicheleAngioni\PhalconAuthAuth(new \MyApp\Users());
    });

Now we can define a simple controller for User registration and login

    <?php
    
    namespace MyApp\Controllers;
    
    use use Phalcon\Mvc\Controller;
    
    class AuthController extends Controller
    {

        public function registerAction()
        {
            $email = $this->request->getPost('email);
            $password = $this->request->getPost('password);
            
            // [..] Validation
        
            $userRepo = new UsersRepository();
    
            try {
                $users = $userRepo->all();
            } catch (\Exception $e) {
                $logger = $this->getDI()->getLogger();
                $logger->error("Caught Exception in ".__METHOD__.' at line '.__LINE__.": {$e->getMessage()}");
    
                $this->setStatusCode(500);
                return $this->respondWithError('Internal error.', 500);
            }
    
            return $this->respondWithCollection($users, new UsersTransformer());
        }
    }


