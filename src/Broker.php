<?php

class Broker
{
    private $broker;

    private $server;

    private $token;

    public function __construct()
    {
        $this->broker = array(
            'id'     => 'broker1',
            'secret' => 'broker1secret',
        );

        $this->server = 'http://server.local/';

        if (isset($_COOKIE[$this->broker['id']])) {
            $this->token = $_COOKIE[$this->broker['id']];
        } else {
            $this->attach();
        }
    }

    public function attach()
    {
        /*
         * Generate random token, and save it to cookie
         */
        // $this->token = uniqid(rand(), true);
        $this->token = base_convert(md5(uniqid(rand(), true)), 16, 36);
        setcookie($this->broker['id'], $this->token, time()+3600, '/'); // 1 hour

        /*
         * Url to redirect
         */
        $current_url = sprintf(
            "%s://%s%s",
            isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off' ? 'https' : 'http',
            $_SERVER['SERVER_NAME'],
            $_SERVER['REQUEST_URI']
        );

        /*
         * Query data
         */
        $query_data = array(
            'command'  => 'attach',
            'broker'   => $this->broker['id'],
            'token'    => $this->token,
            'checksum' => hash('sha256', $this->token.$this->broker['secret']),
            'return'   => $current_url,
        );

        /*
         * Redirect Client to Server
         */
        $url = $this->server.'?'.http_build_query($query_data);
        header("location: $url", true, 307);
        exit;
    }

    private function getUser()
    {
        $result = $this->contactServer('getUser');

        switch ($result['http_code']) {
            case 200: break;
            case 401: {
                header('location: login.php', true, 307);
                exit;
                break;
            }
            default: {
                http_response_code($result['http_code']);
                break;
            }
        }

        return $result['response'];
    }

    private function login($username, $password)
    {
        $result = $this->contactServer('login', 'post', compact('username', 'password'));

        switch ($result['http_code']) {
            case 200: break;
            default: {
                http_response_code($result['http_code']);
                break;
            }
        }

        return $result['response'];
    }

    private function logout()
    {
        $result = $this->contactServer('logout');

        switch ($result['http_code']) {
            case 204: break;
            default: {
                http_response_code($result['http_code']);
                break;
            }
        }

        return $result['response'];
    }

    private function contactServer($command, $method = 'GET', $data = array())
    {
        $method = strtoupper($method);

        /*
         * Query data
         */
        $query_data = array(
            'command' => $command,
            'sid'     => "{$this->broker['id']}-{$this->token}-".hash('sha256', $this->token.$this->broker['secret']),
        );

        if ($method == 'GET' && !empty($data)) {
            $query_data = array_merge($query_data, $data);
        }

        $url = $this->server.'?'.http_build_query($query_data);

        /*
         * Send request to Server
         */
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json'));

        if ($method == 'POST' && !empty($data)) {
            curl_setopt($ch, CURLOPT_POST, 1);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        }

        /*
         * Get response from Server
         */
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if (curl_errno($ch) != 0) {
            $error = curl_error($ch);
            $error = ucfirst(strtolower(str_replace('_', ' ', substr($error, strpos($error, '_')))));
            header("HTTP/1.1 500 $error");
            exit;
        }

        return array(
            'http_code' => $http_code,
            'response'  => $response,
        );
    }
}