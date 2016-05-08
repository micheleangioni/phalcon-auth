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

    /**
     * @expectedException \Exception
     */
    public function testAttemptLoginFailingWrongPassword()
    {
        $di = $this->getDI();
        $security = $di->get('security');

        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->password = $security->hash('password');
        $user->save();

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);
        $auth->attemptLogin($user->email, 'wrong_password');
    }

    /**
     * @expectedException \MicheleAngioni\PhalconAuth\Exceptions\EntityBannedException
     */
    public function testAttemptLoginFailingBanned()
    {
        $di = $this->getDI();
        $security = $di->get('security');
        $session = $di->get('session');

        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->password = $security->hash('password');
        $user->banned = true;
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

    public function testAttemptLoginRememberMe()
    {
        $di = $this->getDI();
        $security = $di->get('security');
        $session = $di->get('session');

        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->password = $security->hash('password');
        $user->save();

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);

        // Inject the request and cookie objects into the auth Service, otherwise they won't won't be found
        $auth->request = new \Phalcon\Http\Request();
        $auth->cookies = new CookiesMock();

        // Login with remember me
        $auth->attemptLogin($user->email, 'password', true, true);

        // Logout
        $auth->logout();

        // Login with remember me
        $auth->loginWithRememberMe();

        // Check if auth session data has been saved
        $auth = $session->get('auth');

        $this->assertTrue(is_array($auth));
        $this->assertArrayHasKey('id', $auth);
        $this->assertArrayHasKey('email', $auth);
    }

    public function testRegister()
    {
        $di = $this->getDI();
        $security = $di->get('security');

        $email = 'email@email.com';
        $password = 'password';
        $text = 'text';

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);
        $auth->register($email, $password, ['text' => $text]);

        $user = $users->findFirst();

        $this->assertEquals(1, $user->getId());
        $this->assertEquals('email@email.com', $user->getEmail());
        $this->assertTrue($security->checkHash('password', $user->getPassword()));
        $this->assertEquals($text, $user->getText());
        $this->assertNotNull($user->getConfirmationCode());
    }

    /**
     * @expectedException \UnexpectedValueException
     */
    public function testRegisterFailingEmailNotUnique()
    {
        $email = 'email@email.com';
        $password = 'password';
        $password2 = 'password2';

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);
        $auth->register($email, $password);
        $auth->register($email, $password2);
    }

    /**
     * @expectedException \UnexpectedValueException
     */
    public function testRegisterFailingTextNotUnique()
    {
        $email = 'email@email.com';
        $password = 'password';
        $text = 'text';

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);
        $auth->register($email, $password, [], ['text' => $text]);
        $auth->register($email, $password, [], ['text' => $text]);
    }

    public function testConfirm()
    {
        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->confirmed = false;
        $user->save();

        $this->assertEquals(false, $user->isConfirmed());

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);
        $auth->confirm($user->getId(), $user->getConfirmationCode());

        $user = $users->findFirst();

        $this->assertEquals(true, $user->isConfirmed());
    }

    /**
     * @expectedException \UnexpectedValueException
     */
    public function testConfirmFailingWrongCode()
    {
        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->confirmed = false;
        $user->save();

        $this->assertEquals(false, $user->isConfirmed());

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);
        $auth->confirm($user->getId(), 'wrong_confiration_code');
    }

    public function testResetPassword()
    {
        $di = $this->getDI();
        $security = $di->get('security');

        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->confirmed = true;
        $user->save();

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);

        $token = $auth->getResetPasswordToken($user->getId());
        $auth->resetPassword($user->getId(), $token, 'newPassword');

        $user = $users->findFirst();

        $this->assertTrue($security->checkHash('newPassword', $user->getPassword()));
    }

    /**
     * @expectedException \UnexpectedValueException
     */
    public function testResetPasswordFailingWrongToken()
    {
        $user = static::$fm->create('MicheleAngioni\PhalconAuth\Tests\Users');
        $user->confirmed = true;
        $user->save();

        $users = new Users();
        $auth = new \MicheleAngioni\PhalconAuth\Auth($users);

        $auth->getResetPasswordToken($user->getId());
        $auth->resetPassword($user->getId(), 'wrong_token', 'newPassword');
    }
}

class Users extends \Phalcon\Mvc\Model implements \MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface
{
    protected $id;

    protected $banned;

    protected $confirmation_code;

    protected $confirmed;

    protected $email;

    protected $password;

    protected $remember_token;

    protected $text;

    public function getId()
    {
        return $this->id;
    }

    public function getConfirmationCode()
    {
        return $this->confirmation_code;
    }

    public function setConfirmationCode($confirmationCode)
    {
        $this->confirmation_code = $confirmationCode;
        return true;
    }

    public function confirm()
    {
        $this->confirmed = true;
        $this->save();
        return true;
    }

    public function isConfirmed()
    {
        return (bool)$this->confirmed;
    }

    public function setConfirmed($confirmed)
    {
        $this->confirmed = $confirmed;
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

    public function getBanned()
    {
        return $this->banned;
    }

    public function setBanned($banned)
    {
        $this->banned = $banned;
    }

    public function isBanned()
    {
        return (bool)$this->banned;
    }

    public function getText()
    {
        return $this->text;
    }
}

class CookiesMock
{
    public $keys = [];

    public function has($key)
    {
        if (isset($this->keys[$key])) {
            return true;
        } else {
            return false;
        }
    }

    public function get($key)
    {
        return $this->keys[$key];
    }

    public function set($key, $value, $expiration = null)
    {
        $this->keys[$key] = new CookieMock($value, $expiration);
    }
}

class CookieMock
{
    public $value;

    public $expiration;

    public function __construct($value, $expiration)
    {
        $this->value = $value;
        $this->expiration = $expiration;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function getExpiration()
    {
        return $this->expiration;
    }
}
