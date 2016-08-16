<?php

require_once __DIR__.'/../vendor/autoload.php';

use Symfony\Component\Cache\Adapter\FilesystemAdapter;

class Server
{
    private $brokers;

    private $users;

    private $cache;

    public function __construct($config)
    {
        $this->brokers = array(
            array(
                'id'     => 'broker1',
                'secret' => 'broker1secret',
            ),
            array(
                'id'     => 'broker2',
                'secret' => 'broker2secret',
            ),
        );

        $this->users = array(
            array(
                'id'       => 1,
                'username' => 'john',
                'email'    => 'john@example.com',
                'password' => 'foo',
                'fullname' => 'John Doe',
            ),
            array(
                'id'       => 2,
                'username' => 'jane',
                'email'    => 'jane@example.com',
                'password' => 'foo',
                'fullname' => 'Jane Roe',
            ),
        );

        $this->cache = new FilesystemAdapter();

        /*
         * Get command to execute
         */
        $command = isset($_REQUEST['command']) ? $_REQUEST['command'] : null;
        if (is_null($command) || !method_exists($this, $command)) {
            header('HTTP/1.1 400 Invalid command');
            exit;
        }

        $this->$command();
    }

    public function attach()
    {
        /*
         * Validate request
         */
        if (empty($_GET['broker']) || empty($_GET['token']) || empty($_GET['checksum']) || empty($_GET['return'])) {
            header('HTTP/1.1 400 Invalid request');
            exit;
        }

        /*
         * Get Broker ID
         */
        $broker_index = array_search($_GET['broker'], array_column($this->brokers, 'id'));
        if ($broker_index === false) {
            header('HTTP/1.1 400 Invalid broker');
            exit;
        }
        $broker = $this->brokers[$broker_index];

        /*
         * Validate checksum
         */
        if (hash('sha256', $_GET['token'].$broker['secret']) != $_GET['checksum']) {
            header('HTTP/1.1 400 Invalid checksum');
            exit;
        }

        /*
         * Create Broker's SID as link to Client session id
         */
        if (session_status() !== PHP_SESSION_ACTIVE) session_start();

        $broker_sid = "{$broker['id']}-{$_GET['token']}-".hash('sha256',$_GET['token'].$broker['secret']);

        /*
         * Save Broker's SID and Client session id to cache
         */
        $item = $this->cache->getItem($broker_sid);
        $item->set(session_id());
        $this->cache->save($item);

        /*
         * Redirect Client to Broker
         */
        header("location: {$_GET['return']}", true, 307);
    }

    private function getUser()
    {
        $this->brokerSession();

        /*
         * Get user's info from user provider
         */
        $user_id = isset($_SESSION['user']) ? $_SESSION['user'] : null;

        $user = $this->loadUser($username);
        if (is_null($user) || $user === false) {
            http_response_code(401);
            exit;
        }

        /*
         * We don't want pass user's password
         */
        unset($user['password']);

        /*
         * Return user info
         */
        http_response_code(200);
        header('Content-Type: application/json; Charset: UTF-8');
        echo json_encode($user);
        exit;
    }

    private function login()
    {
        $this->brokerSession();

        /*
         * Get user's info from user provider
         */
        $user = $this->authenticateUser($_POST['username'], $_POST['password']);
        if (is_null($user) || $user === false) {
            http_response_code(403);
            exit;
        }

        /*
         * We don't want pass user's password
         */
        unset($user['password']);

        /*
         * Store user id to session
         */
        $_SESSION['user'] = $user['id'];

        /*
         * Return user info
         */
        http_response_code(200);
        header('Content-Type: application/json; Charset: UTF-8');
        echo json_encode($user);
        exit;
    }

    private function logout()
    {
        $this->brokerSession();

        unset($_SESSION['user']);

        header('Content-Type: application/json; Charset: UTF-8');
        http_response_code(204);
    }

    private function brokerSession()
    {
        /*
         * Validate request
         */
        if (empty($_GET['sid'])) {
            header('HTTP/1.1 400 Invalid request');
            exit;
        }

        /*
         * Validate SID, parse broker and token from SID
         */
        // "{$this->broker['id']}-{$this->token}-".hash('sha256', $this->token.$this->broker['secret'])
        $valid = preg_match('/^(\w*+)-(\w*+)-([a-z0-9]*+)$/', $_GET['sid'], $matches);
        if ($valid === false) {
            header('HTTP/1.1 400 Invalid SID');
            exit;
        }

        $broker_id = isset($matches[1]) ? $matches[1] : null;
        $token     = isset($matches[2]) ? $matches[2] : null;
        if (is_null($broker_id) || is_null($token)) {
            header('HTTP/1.1 400 Invalid SID');
            exit;
        }

        $broker_index = array_search($broker_id, array_column($this->brokers, 'id'));
        if ($broker_index === false) {
            header('HTTP/1.1 400 Invalid SID');
            exit;
        }
        $broker = $this->brokers[$broker_index];

        /*
         * Revalidate SID based on broker and token
         */
        if ($_GET['sid'] != "{$broker['id']}-{$token}-".hash('sha256',$token.$broker['secret'])) {
            header('HTTP/1.1 400 Invalid SID');
            exit;
        }

        /*
         * Search for cache
         */
        $broker_sid = $_GET['sid'];

        $item = $this->cache->getItem($broker_sid);

        if ($item->isHit() === false) {
            echo 'Not attached';
            header('HTTP/1.1 400 Not attached');
            exit;
        }
        $session_id = $item->get();

        /*
         * Create broker session and set the session id = client session id
         */
        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($session_id != session_id()) {
                header('HTTP/1.1 400 Session already started');
                exit;
            }
        }
        session_id($session_id);
        session_start();
    }

    private function loadUser($username)
    {
        $user_index = !is_null($user_id) ? array_search($user_id, array_column($this->users, 'id')) : false;

        $user = $user_index !== false ? $this->users[$user_index] : null;

        return $user;
    }

    private function authenticateUser($username, $password)
    {
        $user_index = !is_null($username) ? array_search($username, array_column($this->users, 'username')) : false;

        $user = $user_index !== false ? $this->users[$user_index] : null;

        if ($password != $user['password']) {
            return false;
        }

        return $user;
    }
}