<?php

namespace MicheleAngioni\PhalconAuth\Contracts;

interface RememberableAuthableInterface extends AuthableInterface
{
    /**
     * Must return the model remember token.
     *
     * @return string
     */
    public function getRememberToken();

    /**
     * Must set the model remember token and return true on success, false otherwise.
     *
     * @param  string
     *
     * @return bool
     */
    public function setRememberToken($token);

}
