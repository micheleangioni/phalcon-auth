<?php

namespace Learnph\Tests;

use League\FactoryMuffin\Faker\Facade as Faker;

$fm->define('MicheleAngioni\PhalconAuth\Tests\Users')->setDefinitions([
    'email'    => Faker::email(),
    'password' => Faker::password(),
    'rememberDoken' => Faker::regexify('[A-Z0-9._%+-]{20,40}')
]);
