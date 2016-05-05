<?php

namespace MicheleAngioni\PhalconAuth\Tests;

use League\FactoryMuffin\FactoryMuffin;

class AuthWebTest extends TestCase
{
    protected static $fm;

    public static function setupBeforeClass()
    {
        // create a new factory muffin instance
        static::$fm = new FactoryMuffin();

        // you can customize the save/delete methods
        // new FactoryMuffin(new ModelStore('save', 'delete'));

        // load your model definitions
        static::$fm->loadFactories(__DIR__.'/factories');

        parent::setUpBeforeClass();
    }

    public function testAttemptLogin()
    {
        $di = $this->getDI();
        $security = $di->get('security');
        $session = $di->get('session');

        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->password = $security->hash('password');
        $user->save();

        $users = new Users();

        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);

        $auth->attemptLogin($user->email, 'password');

        // Check if auth session data has been saved
        $auth = $session->get('auth');

        $this->assertTrue(is_array($auth));
        $this->assertArrayHasKey('id', $auth);
        $this->assertArrayHasKey('email', $auth);
    }
}

class Users extends \Phalcon\Mvc\Model implements \MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface
{
    protected $id;

    protected $email;

    protected $password;

    protected $rememberToken;

    public function getId()
    {
        return $this->id;
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
        return $this->rememberToken;
    }

    public function setRememberToken($token)
    {
        $this->rememberToken = $token;
        $this->save();
    }
}
