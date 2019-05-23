<?php

class JSSDK {

    private $appId;
    private $appSecret;
    private $cardId;
    private $openid = '';
    private $code = '';
    public $ip;

    public function __construct($appId, $appSecret, $cardId = "", $openid = "") {
        $this->appId = $appId;
        $this->appSecret = $appSecret;
        $this->cardId = $cardId;
        $this->openid = $openid;
        //$this->ip = $_SERVER['REMOTE_ADDR'];
    }

    public function getSignPackage() {
        $jsapiTicket = $this->getJsApiTicket();
        // 注意 URL 一定要动态获取，不能 hardcode.
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

        $timestamp = time();
        $nonceStr = $this->createNonceStr();

        // 这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";

        $signature = sha1($string);

        $signPackage = array(
            "appId" => $this->appId,
            "nonceStr" => $nonceStr,
            "timestamp" => $timestamp,
            "url" => $url,
            "signature" => $signature,
            "rawString" => $string
        );
        return $signPackage;
    }

    public function getOpenId($myurl='') {
        if (!empty($this->openid)) {
            return $this->openid;
        }
        $code = trim($_GET['code']);
        if (strlen($code) > 0) {
            $url = 'https://api.weixin.qq.com/sns/oauth2/access_token?appid=' . $this->appId . '&secret=' . $this->appSecret . '&code=' . $code . '&grant_type=authorization_code';
            $res = json_decode($this->httpGet($url));
            $openid = $res->openid;
            if (empty($openid)) {
                $redirect_uri = empty($myurl)?"http://" . $_SERVER['HTTP_HOST']:$myurl;
                header('Location:' . $redirect_uri);
                exit();
            } else {
                $this->openid = $openid;
                return $openid;
            }
        } else {
            $url = "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
            $redirect_uri = 'https://open.weixin.qq.com/connect/oauth2/authorize?appid=' . $this->appId . '&redirect_uri=' . urlencode($url) . '&response_type=code&scope=snsapi_base&state=STATE#wechat_redirect';
            header('Location:' . $redirect_uri);
            exit();
        }
    }

    public function getCardPackage() {
        $cardapiTicket = $this->getCardApiTicket();
        $timestamp = time();
        $nonceStr = $this->createNonceStr();
        $tmparr = array($this->code, strval($timestamp), $cardapiTicket, $this->cardId, $this->openid, strval($nonceStr));
        sort($tmparr);
        $string = implode('', $tmparr);
        $signature = sha1($string);
        $signPackage = array(
            "code" => $this->code,
            "openid" => $this->openid,
            "cardId" => $this->cardId,
            "nonceStr" => $nonceStr,
            "timestamp" => $timestamp,
            "signType" => 'SHA1',
            "cardSign" => $signature,
            'str' => $string
        );
        return $signPackage;
    }

    private function createNonceStr($length = 16) {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    private function getJsApiTicket() {
        // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例
        $data = json_decode(file_get_contents(dirname(__FILE__) . "/jsapi_ticket.json"));
        if ( $data->appId != $this->appId || $data->expire_time < time()) {
            $accessToken = $this->getAccessToken();
            // 如果是企业号用以下 URL 获取 ticket
            // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=$accessToken";
            $res = json_decode($this->httpGet($url));
            $ticket = $res->ticket;
            if ($ticket) {
                $data->expire_time = time() + 7000;
                $data->jsapi_ticket = $ticket;
                $data->appId = $this->appId;
                file_put_contents(dirname(__FILE__) . '/jsapi_ticket.json', json_encode($data));
                //$fp = fopen("/jssdk/jsapi_ticket.json", "w");
                //fwrite($fp, json_encode($data));
                //fclose($fp);
            }
        } else {
            $ticket = $data->jsapi_ticket;
        }
        return $ticket;
    }

    public function getCardApiTicket() {
        $data = json_decode(file_get_contents(dirname(__FILE__) . "/cardapi_ticket.json"));
        if ($data->appId != $this->appId || $data->expire_time < time()) {
            $accessToken = $this->getAccessToken();
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token=" . $accessToken . "&type=wx_card";
            $res = json_decode($this->httpGet($url));
            $ticket = $res->ticket;
            if ($ticket) {
                $data->expire_time = time() + 7000;
                $data->cardapi_ticket = $ticket;
                $data->appId = $this->appId;
                file_put_contents(dirname(__FILE__) . '/cardapi_ticket.json', json_encode($data));
            }
        } else {
            $ticket = $data->cardapi_ticket;
        }
        return $ticket;
    }

    private function getAccessToken() {
        // access_token 应该全局存储与更新，以下代码以写入到文件中做示例
        $data = json_decode(file_get_contents(dirname(__FILE__) . "/access_token.json"));
        if ($data->appId != $this->appId || $data->expire_time < time()) {
            // 如果是企业号用以下URL获取access_token
            // $url = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=$this->appId&corpsecret=$this->appSecret";
            $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=$this->appId&secret=$this->appSecret";
            $res = json_decode($this->httpGet($url));
            $access_token = $res->access_token;
            if ($access_token) {
                $data->expire_time = time() + 7000;
                $data->access_token = $access_token;
                $data->appId = $this->appId;
                file_put_contents(dirname(__FILE__) . '/access_token.json', json_encode($data));
                /* $fp = fopen("/jssdk/access_token.json", "w");
                  fwrite($fp, json_encode($data));
                  fclose($fp); */
            }
        } else {
            $access_token = $data->access_token;
        }
        return $access_token;
    }

    private function httpGet($url) {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl, CURLOPT_URL, $url);
        $res = curl_exec($curl);
        curl_close($curl);
        return $res;
    }
}
