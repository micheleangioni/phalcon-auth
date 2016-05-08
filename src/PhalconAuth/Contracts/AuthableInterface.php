<?php

namespace MicheleAngioni\PhalconAuth\Contracts;

interface AuthableInterface extends \Phalcon\Mvc\ModelInterface
{
    /**
     * Must return the model id.
     *
     * @return int
     */
    public function getId();

    /**
     * Must return the model email.
     *
     * @return string
     */
    public function getEmail();

    /**
     * Must return the model password.
     *
     * @return string
     */
    public function getPassword();

    /**
     * Must set the model password and return true on success.
     *
     * @param  string $password
     *
     * @return bool
     */
    public function setPassword($password);

    /**
     * Must return the model confirmation code.
     *
     * @return string
     */
    public function getConfirmationCode();

    /**
     * Must set the model confirmation code and return true on success.
     *
     * @param  string $confirmationCode
     *
     * @return bool
     */
    public function setConfirmationCode($confirmationCode);

    /**
     * Must set the model as confirmed and return true on success.
     *
     * @return bool
     */
    public function confirm();

    /**
     * Must check if the model is confirmed or not.
     *
     * @return bool
     */
    public function isConfirmed();

    /**
     * Must check if the model is banned or not.
     *
     * @return bool
     */
    public function isBanned();

}
