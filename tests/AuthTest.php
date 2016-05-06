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
    public function testAttemptLoginFailing()
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
}

class Users extends \Phalcon\Mvc\Model implements \MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface
{
    protected $id;

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
        return true;
    }

    public function getText()
    {
        return $this->text;
    }
}
