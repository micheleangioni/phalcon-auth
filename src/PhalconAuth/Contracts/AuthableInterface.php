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

}
