<?php

namespace MicheleAngioni\PhalconAuth;

use MicheleAngioni\PhalconAuth\Contracts\AuthableInterface;
use MicheleAngioni\PhalconAuth\Contracts\RememberableAuthableInterface;
use Phalcon\Mvc\User\Component;
use Exception;
use MicheleAngioni\PhalconAuth\Exceptions\EntityBannedException;
use MicheleAngioni\PhalconAuth\Exceptions\RememberMeTokenExpired;
use InvalidArgumentException;
use RuntimeException;
use UnexpectedValueException;

class Auth extends Component
{
    /**
     * Duration in seconds of the remember me feature.
     */
    const REMEMBER_ME_DURATION = 604800; // 1w

    /**
     * @var AuthableInterface
     */
    protected $authable;

    /**
     * Options array
     *
     * @var array
     */
    protected $options;

    /**
     * Auth constructor.
     * Available options in $options array:
     *  'rememberMeDuration' : int, duration of the remember me feature, in seconds
     *
     * @param  AuthableInterface  $authable
     * @param  array  $options
     */
    public function __construct(AuthableInterface $authable, array $options = [])
    {
        $this->authable = $authable;

        $this->options = $options;
    }

    /**
     * Create a new User with email (must be unique) and password.
     * An $uniqueParameters array can be passed. A check will be made if those values have been already taken.
     *
     * @param  string  $email
     * @param  string  $password
     * @throws RuntimeException
     * @throws UnexpectedValueException
     *
     * @return \Phalcon\Mvc\Model\ResultsetInterface
     */
    public function register($email, $password, array $parameters = [], array $uniqueParameters = [], $addConfirmationCode = true)
    {
        // Check if the email is already taken

        if ($this->authable->findFirstByEmail($email)) {
            throw new UnexpectedValueException('Email already taken.');
        }

        // Check for unique parameters

        foreach($uniqueParameters as $key => $value) {
            $searchKey = 'findFirstBy' . ucfirst($key);

            if ($this->authable->$searchKey($value)) {
                throw new UnexpectedValueException($searchKey . ' already taken.');
            }
        }

        // Create and store the new Entity

        $className = get_class($this->authable);
        $entity = new $className;

        $credentials = [
            'email' => $email,
            'password' => $this->security->hash($password)
        ];

        if ($addConfirmationCode) {
            $credentials['confirmation_code'] = md5(uniqid(mt_rand(), true));
        }

        $data = array_merge(array_merge($parameters, $uniqueParameters), $credentials);

        try {
            $entity->save($data);
        } catch (\Exception $e) {
            throw new RuntimeException('Caught RuntimeException in '.__METHOD__.' at line '.__LINE__.': error creating new authable model.');
        }

        if (count($entity->getMessages())) {
            $messages = '';

            foreach ($entity->getMessages() as $message) {
                $messages .= $message . ' ';
            }

            throw new RuntimeException('Caught RuntimeException in '.__METHOD__.' at line '.__LINE__.': error creating new authable model: ' . $messages);
        }

        return $entity;
    }

    /**
     * Attempt login of the authable entity credentials.
     *
     * @param  array  $credentials
     * @param  bool  $saveSession
     * @throws Exception
     *
     * @return AuthableInterface
     */
    public function attemptLogin($email, $password, $saveSession = true, $rememberMe = false)
    {
        // Check if the entity exist
        $entity = $this->authable->findFirstByEmail($email);

        if ($entity === false) {
            $this->registerUserThrottling(0);
            throw new Exception('Wrong email/password combination');
        }

        // Check the password
        if (!$this->security->checkHash($password, $entity->password)) {
            $this->registerUserThrottling($entity->id);
            throw new Exception('Wrong email/password combination');
        }

        // Check if the entity is banned

        if ($entity->isBanned()) {
            throw new EntityBannedException('The entity is banned');
        }

        // If required, save the entity data into the session

        if ($saveSession) {
            $this->saveSessionData($entity);

            // Check if the remember me was selected
            if ($rememberMe) {
                $this->createRememberEnvironment($entity);
            }
        }

        return $entity;
    }

    /**
     * Implements login throttling
     * Reduces the effectiveness of brute force attacks (both on same user from different ips and on different users with same ip).
     *
     * @param  int  $userId
     */
    public function registerUserThrottling($userId)
    {
        // TODO Set up a user throttling with Cache

        /*
        switch ($attempts) {
            case 1:
            case 2:
                // no delay
                break;
            case 3:
            case 4:
                sleep(2);
                break;
            default:
                sleep(4);
                break;
        }
        */
    }

    /**
     * Creates the remember me environment settings, i.e. the related cookies and generating the token.
     *
     * @param  RememberableAuthableInterface  $entity
     */
    public function createRememberEnvironment(RememberableAuthableInterface $entity)
    {
        $userAgent = $this->request->getUserAgent();
        $token = md5($entity->getEmail() . $entity->getPassword() . $userAgent);

        $entity->setRememberToken($token);
        $entity->save();

        $expire = time() + $this->getRememberMeDuration();

        $this->cookies->set('RMU', $entity->getId(), $expire);
        $this->cookies->set('RMT', $token, $expire);
    }

    /**
     * Check if the session has a remember me environemnt set.
     *
     * @return boolean
     */
    public function hasRememberMe()
    {
        return $this->cookies->has('RMU') && $this->cookies->has('RMT');
    }

    /**
     * Log in using the information in the cookies.
     *
     * @throws Exception
     * @return AuthableInterface
     */
    public function loginWithRememberMe()
    {
        // Check if cookies are present
        if (!$this->hasRememberMe()) {
            // Clean the environment
            $this->remove();

            throw new UnexpectedValueException('Remember me were not set.');
        }

        // Retrieve the remember me data

        $cookieEntity = $this->cookies->get('RMU');
        $entityId = $cookieEntity->getValue();

        $cookieToken = $this->cookies->get('RMT');
        $cookieTokenValue = $cookieToken->getValue();

        // Retrieve the previously authenticated user and check if it correctly exists

        $entity = $this->retrieveAuthableById($entityId);

        if ($entity) {
            $userAgent = $this->request->getUserAgent();
            $token = md5($entity->getEmail() . $entity->getPassword() . $userAgent);

            if ($cookieTokenValue == $token) {
                // Check if the cookie has not expired

                if (time() < $cookieToken->getExpiration()) {
                    // Check if the entity is banned

                    if ($entity->isBanned()) {
                        throw new EntityBannedException('The entity is banned');
                    }

                    // Save the User data into the session
                    $this->saveSessionData($entity);

                    return $entity;
                }

                throw new RememberMeTokenExpired('Remember me token is expired');
            }
        }

        // Clean the environment since something went wrong
        $this->remove();

        throw new UnexpectedValueException('Authable entity not found');
    }

    /**
     * Returns the current identity.
     *
     * @return array
     */
    public function getIdentity()
    {
        return $this->session->get('auth');
    }

    /**
     * Returns the current identity email.
     *
     * @return string
     */
    public function getEmail()
    {
        $identity = $this->session->get('auth');
        return $identity['email'];
    }

    /**
     * Removes the entity identity information from remember me cookies and session.
     */
    protected function remove()
    {
        // Destroy the remember me environment

        if ($this->cookies->has('RMU')) {
            $this->cookies->get('RMU')->delete();
        }

        if ($this->cookies->has('RMT')) {
            $this->cookies->get('RMT')->delete();
        }

        // Logout the entity
        $this->logout();
    }

    /**
     * Logout the entity, i.e. removes the session data but keeps the remember me environment.
     */
    public function logout()
    {
        $this->session->remove('auth');
    }

    /**
     * Auth the authable model by id.
     *
     * @param  int  $id
     * @throws Exception
     */
    public function authById($id)
    {
        $entity = $this->authable->findFirstById($id);

        if ($entity == false) {
            throw new Exception('The user does not exist');
        }

        // Check if the entity is banned

        if ($entity->isBanned()) {
            throw new EntityBannedException('The entity is banned');
        }

        // Save the User data into the session
        $this->saveSessionData($entity);
    }

    /**
     * Retrieve and return the authable model by id.
     * Return null if the User is not found.
     *
     * @throws Exception
     * @return AuthableInterface|null
     */
    public function retrieveAuthableById($id)
    {
        $entity = $this->authable->findFirstById($id);

        if ($entity == false) {
            return null;
        }

        return $entity;
    }

    /**
     * Get the stored authenticated entity.
     * Return false if no authentication has been made.
     *
     * @throws Exception
     * @return AuthableInterface|bool
     */
    public function getAuth()
    {
        $identity = $this->session->get('auth');

        if (isset($identity['id'])) {
            if (!$user = $this->retrieveAuthableById($identity['id'])) {
                throw new Exception('The authenticated model does not exist');
            }

            return $user;
        }

        return false;
    }

    /**
     * Save the User data into the Session.
     *
     * @param  AuthableInterface  $entity
     */
    protected function saveSessionData(AuthableInterface $entity)
    {
        $this->session->set('auth', [
            'id' => $entity->getId(),
            'email' => $entity->getEmail()
        ]);
    }

    /**
     * @throws InvalidArgumentException
     * @return int
     */
    protected function getRememberMeDuration()
    {
        if (isset($this->options['rememberMeDuration'])) {
            if (!is_int($this->options['rememberMeDuration'])) {
                throw new InvalidArgumentException('The rememberMeDuration option must be a valid integer');
            }

            return $this->options['rememberMeDuration'];
        }

        return self::REMEMBER_ME_DURATION;
    }
}
