<?php

namespace kafene;

class MCrypt {
    public static function encrypt($key, $data, array $options = []) {
        $algorithm = empty($options['algorithm']) ?
                MCRYPT_RIJNDAEL_256 :
                $options['algorithm'];

        $mode = empty($options['mode']) ?
                MCRYPT_MODE_CBC :
                $options['mode'];

        $ivSize = mcrypt_get_iv_size($algorithm, $mode);
        $keySize = mcrypt_get_key_size($algorithm, $mode);

        $iv = empty($options['iv']) ?
            mcrypt_create_iv($ivSize, MCRYPT_DEV_URANDOM) :
            $options['iv'];

        $iv = substr($iv, 0, $ivSize);
        $key = substr($key, 0, $keySize);

        $encrypted = mcrypt_encrypt($algorithm, $key, $data, $mode, $iv);
        $encrypted = base64_encode($encrypted);

        $iv = base64_encode($iv);

        $data = json_encode([
            'iv' => $iv,
            'data' => $encrypted,
            'algorithm' => $algorithm,
            'mode' => $mode,
        ], JSON_HEX_QUOT|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_TAG);

        return $data;
    }

    public static function decrypt($key, $data) {
        $data = is_array($data) ? $data : json_decode($data, true);

        $algorithm = $data['algorithm'];
        $mode = $data['mode'];

        $ivSize = mcrypt_get_iv_size($algorithm, $mode);
        $keySize = mcrypt_get_key_size($algorithm, $mode);

        $iv = base64_decode($data['iv']);
        $encrypted = base64_decode($data['data']);

        $iv = substr($iv, 0, $ivSize);
        $key = substr($key, 0, $keySize);

        $decrypted = mcrypt_decrypt($algorithm, $key, $encrypted, $mode, $iv);
        $decrypted = rtrim($decrypted, "\0");

        return $decrypted;
    }
}

