<?php

require_once __DIR__.'/../src/Broker.php';

$broker = new Broker();
$user = $broker->login('john', 'foo');