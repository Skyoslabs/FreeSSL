<?php
declare(strict_types=1);
// Free SSL v1.1.0
/*
MIT License

Copyright (c) 2026 freessl contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
/*
  MIT License

  Copyright (c) 2018 Stefan Körfgen

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

// https://github.com/skoerfgen/ACMECert

namespace skoerfgen\ACMECert {

use Exception;

class ACME_Exception extends Exception {
	private $type,$subproblems;
	function __construct($type,$detail,$subproblems=array()){
		$this->type=$type;
		$this->subproblems=$subproblems;
		parent::__construct($detail.' ('.$type.')');
	}
	function getType(){
		return $this->type;
	}
	function getSubproblems(){
		return $this->subproblems;
	}
}

}
/*
  MIT License

  Copyright (c) 2018 Stefan Körfgen

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

// https://github.com/skoerfgen/ACMECert

namespace skoerfgen\ACMECert {

use Exception;
use skoerfgen\ACMECert\ACME_Exception;

class ACMEv2 { // Communication with Let's Encrypt via ACME v2 protocol

	protected
		$directories=array(
			'live'=>'https://acme-v02.api.letsencrypt.org/directory',
			'staging'=>'https://acme-staging-v02.api.letsencrypt.org/directory'
		),$ch=null,$logger=true,$bits,$sha_bits,$directory,$resources,$jwk_header,$kid_header,$account_key,$thumbprint,$nonce=null,$delay_until=null;

	public function __construct($live=true){
		if (is_bool($live)){ // backwards compatibility to ACMECert v3.1.2 or older
			$this->directory=$this->directories[$live?'live':'staging'];
		}else{
			$this->directory=$live;
		}
	}

	public function __destruct(){
		if (PHP_MAJOR_VERSION<8){
			if ($this->account_key) openssl_pkey_free($this->account_key);
			if ($this->ch) curl_close($this->ch);
		}
	}

	public function loadAccountKey($account_key_pem){
		if (PHP_MAJOR_VERSION<8 && $this->account_key) openssl_pkey_free($this->account_key);
		if (false===($this->account_key=openssl_pkey_get_private($account_key_pem))){
			throw new Exception('Could not load account key: '.$account_key_pem.' ('.$this->get_openssl_error().')');
		}

		if (false===($details=openssl_pkey_get_details($this->account_key))){
			throw new Exception('Could not get account key details: '.$account_key_pem.' ('.$this->get_openssl_error().')');
		}

		$this->bits=$details['bits'];
		switch($details['type']){
			case OPENSSL_KEYTYPE_EC:
				if (version_compare(PHP_VERSION,'7.1.0')<0) throw new Exception('PHP >= 7.1.0 required for EC keys !');
				$this->sha_bits=($this->bits==521?512:$this->bits);
				$this->jwk_header=array( // JOSE Header - RFC7515
					'alg'=>'ES'.$this->sha_bits,
					'jwk'=>array( // JSON Web Key
						'crv'=>'P-'.$details['bits'],
						'kty'=>'EC',
						'x'=>$this->base64url(str_pad($details['ec']['x'],ceil($this->bits/8),"\x00",STR_PAD_LEFT)),
						'y'=>$this->base64url(str_pad($details['ec']['y'],ceil($this->bits/8),"\x00",STR_PAD_LEFT))
					)
				);
			break;
			case OPENSSL_KEYTYPE_RSA:
				$this->sha_bits=256;
				$this->jwk_header=array( // JOSE Header - RFC7515
					'alg'=>'RS256',
					'jwk'=>array( // JSON Web Key
						'e'=>$this->base64url($details['rsa']['e']), // public exponent
						'kty'=>'RSA',
						'n'=>$this->base64url($details['rsa']['n']) // public modulus
					)
				);
			break;
			default:
				throw new Exception('Unsupported key type! Must be RSA or EC key.');
			break;
		}

		$this->kid_header=array(
			'alg'=>$this->jwk_header['alg'],
			'kid'=>null
		);

		$this->thumbprint=$this->base64url( // JSON Web Key (JWK) Thumbprint - RFC7638
			hash(
				'sha256',
				json_encode($this->jwk_header['jwk']),
				true
			)
		);
	}

	public function getAccountID(){
		if (!$this->kid_header['kid']) self::getAccount();
		return $this->kid_header['kid'];
	}

	public function setLogger($value=true){
		switch(true){
			case is_bool($value):
			break;
			case is_callable($value):
			break;
			default:
				throw new Exception('setLogger: invalid value provided');
			break;
		}
		$this->logger=$value;
	}

	public function log($txt){
		switch(true){
			case $this->logger===true:
				error_log($txt);
			break;
			case $this->logger===false:
			break;
			default:
				$fn=$this->logger;
				$fn($txt);
			break;
		}
	}

	protected function create_ACME_Exception($type,$detail,$subproblems=array()){
		$this->log('ACME_Exception: '.$detail.' ('.$type.')');
		return new ACME_Exception($type,$detail,$subproblems);
	}

	protected function get_openssl_error(){
		$out=array();
		$arr=error_get_last();
		if (is_array($arr)){
			$out[]=$arr['message'];
		}
		$out[]=openssl_error_string();
		return implode(' | ',$out);
	}

	protected function getAccount(){
		$this->log('Getting account info');
		$ret=$this->request('newAccount',array('onlyReturnExisting'=>true));
		$this->log('Account info retrieved');
		return $ret;
	}

	protected function keyAuthorization($token){
		return $token.'.'.$this->thumbprint;
	}

	protected function readDirectory(){
		$this->log('Initializing ACME v2 environment: '.$this->directory);
		$ret=$this->http_request($this->directory); // Read ACME Directory
		if (
			!is_array($ret['body']) ||
			!empty(
				array_diff_key(
					array_flip(array('newNonce','newAccount','newOrder')),
					$ret['body']
				)
			)
		){
			throw new Exception('Failed to read directory: '.$this->directory);
		}
		$this->resources=$ret['body']; // store resources for later use
		$this->log('Initialized');
	}

	protected function request($type,$payload='',$retry=false){
		if (!$this->jwk_header) {
			throw new Exception('use loadAccountKey to load an account key');
		}

		if (!$this->resources) $this->readDirectory();

		if (0===stripos($type,'http')) {
			$this->resources['_tmp']=$type;
			$type='_tmp';
		}

		try {
			$ret=$this->http_request($this->resources[$type],json_encode(
				$this->jws_encapsulate($type,$payload)
			));
		}catch(ACME_Exception $e){ // retry previous request once, if replay-nonce expired/failed
			if (!$retry && $e->getType()==='urn:ietf:params:acme:error:badNonce') {
				$this->log('Replay-Nonce expired, retrying previous request');
				return $this->request($type,$payload,true);
			}
			if (!$retry && $e->getType()==='urn:ietf:params:acme:error:rateLimited' && $this->delay_until!==null) {
				return $this->request($type,$payload,true);
			}
			throw $e; // rethrow all other exceptions
		}

		if (!$this->kid_header['kid'] && $type==='newAccount'){
			$this->kid_header['kid']=$ret['headers']['location'];
			$this->log('AccountID: '.$this->kid_header['kid']);
		}

		return $ret;
	}

	protected function jws_encapsulate($type,$payload,$is_inner_jws=false){ // RFC7515
		if ($type==='newAccount' || $is_inner_jws) {
			$protected=$this->jwk_header;
		}else{
			$this->getAccountID();
			$protected=$this->kid_header;
		}

		if (!$is_inner_jws) {
			if (!$this->nonce) {
				$ret=$this->http_request($this->resources['newNonce'],false);
			}
			$protected['nonce']=$this->nonce;
			$this->nonce=null;
		}

		if (!isset($this->resources[$type])){
			throw new Exception('Resource "'.$type.'" not available.');
		}

		$protected['url']=$this->resources[$type];

		$protected64=$this->base64url(json_encode($protected,JSON_UNESCAPED_SLASHES));
		$payload64=$this->base64url(is_string($payload)?$payload:json_encode($payload,JSON_UNESCAPED_SLASHES));

		if (false===openssl_sign(
			$protected64.'.'.$payload64,
			$signature,
			$this->account_key,
			'SHA'.$this->sha_bits
		)){
			throw new Exception('Failed to sign payload !'.' ('.$this->get_openssl_error().')');
		}

		return array(
			'protected'=>$protected64,
			'payload'=>$payload64,
			'signature'=>$this->base64url($this->jwk_header['alg'][0]=='R'?$signature:$this->asn2signature($signature,ceil($this->bits/8)))
		);
	}

	private function asn2signature($asn,$pad_len){
		if ($asn[0]!=="\x30") throw new Exception('ASN.1 SEQUENCE not found !');
		$asn=substr($asn,$asn[1]==="\x81"?3:2);
		if ($asn[0]!=="\x02") throw new Exception('ASN.1 INTEGER 1 not found !');
		$R=ltrim(substr($asn,2,ord($asn[1])),"\x00");
		$asn=substr($asn,ord($asn[1])+2);
		if ($asn[0]!=="\x02") throw new Exception('ASN.1 INTEGER 2 not found !');
		$S=ltrim(substr($asn,2,ord($asn[1])),"\x00");
		return str_pad($R,$pad_len,"\x00",STR_PAD_LEFT).str_pad($S,$pad_len,"\x00",STR_PAD_LEFT);
	}

	protected function base64url($data){ // RFC7515 - Appendix C
		return rtrim(strtr(base64_encode($data),'+/','-_'),'=');
	}

	protected function base64url_decode($data){
		return base64_decode(strtr($data,'-_','+/'));
	}

	private function json_decode($str){
		$ret=json_decode($str,true);
		if ($ret===null) {
			throw new Exception('Could not parse JSON: '.$str);
		}
		return $ret;
	}

	protected function http_request($url,$data=null){
		if ($this->ch===null) {
			if (extension_loaded('curl') && $this->ch=curl_init()) {
				$this->log('Using cURL');
			}elseif(ini_get('allow_url_fopen')){
				$this->ch=false;
				$this->log('Using fopen wrappers');
			}else{
				throw new Exception('Can not connect, no cURL or fopen wrappers enabled !');
			}
		}

		if ($this->delay_until!==null){
			$delta=$this->delay_until-time();
			if ($delta>0 && $delta<300){ // ignore delay if not in range 1s..5min
				$this->log('Delaying '.$delta.'s (rate limit)');
				sleep($delta);
			}
			$this->delay_until=null;
		}

		$method=$data===false?'HEAD':($data===null?'GET':'POST');
		$user_agent='ACMECert v3.7.3 (+https://github.com/skoerfgen/ACMECert)';
		$header=($data===null||$data===false)?array():array('Content-Type: application/jose+json');
		if ($this->ch) {
			$headers=array();
			curl_setopt_array($this->ch,array(
				CURLOPT_URL=>$url,
				CURLOPT_FOLLOWLOCATION=>true,
				CURLOPT_RETURNTRANSFER=>true,
				CURLOPT_TCP_NODELAY=>true,
				CURLOPT_NOBODY=>$data===false,
				CURLOPT_USERAGENT=>$user_agent,
				CURLOPT_CUSTOMREQUEST=>$method,
				CURLOPT_HTTPHEADER=>$header,
				CURLOPT_POSTFIELDS=>$data,
				CURLOPT_HEADERFUNCTION=>static function($ch,$header)use(&$headers){
					$headers[]=$header;
					return strlen($header);
				}
			));
			$took=microtime(true);
			$body=curl_exec($this->ch);
			$took=round(microtime(true)-$took,2).'s';
			if ($body===false) throw new Exception('HTTP Request Error: '.curl_error($this->ch));
		}else{
			$opts=array(
				'http'=>array(
					'header'=>$header,
					'method'=>$method,
					'user_agent'=>$user_agent,
					'ignore_errors'=>true,
					'timeout'=>60,
					'content'=>$data
				)
			);
			$took=microtime(true);
			$body=file_get_contents($url,false,stream_context_create($opts));
			$took=round(microtime(true)-$took,2).'s';
			if ($body===false) throw new Exception('HTTP Request Error: '.$this->get_openssl_error());
			if (PHP_VERSION_ID>=80400){
				$http_response_header=http_get_last_response_headers();
			}
			$headers=$http_response_header;
		}

		$headers=array_reduce( // parse http response headers into array
			array_filter($headers,function($item){ return trim($item)!=''; }),
			function($carry,$item)use(&$code){
				$parts=explode(':',$item,2);
				if (count($parts)===1){
					list(,$code)=explode(' ',trim($item),3);
					$carry=array();
				}else{
					list($k,$v)=$parts;
					$k=strtolower(trim($k));
					switch($k){
						case 'link':
							if (preg_match('/<(.*)>\s*;\s*rel=\"(.*)\"/',$v,$matches)){
								$carry[$k][$matches[2]][]=trim($matches[1]);
							}
						break;
						case 'content-type':
							list($v)=explode(';',$v,2);
						default:
							$carry[$k]=trim($v);
						break;
					}
				}
				return $carry;
			},
			array()
		);
		$this->log('  '.$url.' ['.$code.'] ('.$took.')');

		if (!empty($headers['replay-nonce'])) $this->nonce=$headers['replay-nonce'];

		if (isset($headers['retry-after'])){
			$this->delay_until=$this->parseRetryAfterHeader($headers['retry-after'])+time();
		}

		if (!empty($headers['content-type'])){
			switch($headers['content-type']){
				case 'application/json':
					if ($code[0]=='2'){ // on non 2xx response: fall through to problem+json case
						$body=$this->json_decode($body);
						if (isset($body['error']) && !(isset($body['status']) && $body['status']==='valid')) {
							$this->handleError($body['error']);
						}
						break;
					}
				case 'application/problem+json':
					$body=$this->json_decode($body);
					$this->handleError($body);
				break;
			}
		}

		if ($code[0]!='2') {
			throw new Exception('Invalid HTTP-Status-Code received: '.$code.': '.print_r($body,true));
		}

		$ret=array(
			'code'=>$code,
			'headers'=>$headers,
			'body'=>$body
		);

		return $ret;
	}

	protected function parseRetryAfterHeader($h){
		if (is_numeric($h)){
			return (int)$h;
		}else{
			$ts=strtotime($h);
			return $ts===false?0:max(0,$ts-time());
		}
	}

	private function handleError($error){
		throw $this->create_ACME_Exception($error['type'],$error['detail'],
			array_map(function($subproblem){
				return $this->create_ACME_Exception(
					$subproblem['type'],
					(isset($subproblem['identifier']['value'])?
						'"'.$subproblem['identifier']['value'].'": ':
						''
					).$subproblem['detail']
				);
			},isset($error['subproblems'])?$error['subproblems']:array())
		);
	}

}

}
/*
  MIT License

  Copyright (c) 2018 Stefan Körfgen

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

// https://github.com/skoerfgen/ACMECert

namespace skoerfgen\ACMECert {

use skoerfgen\ACMECert\ACMEv2;
use skoerfgen\ACMECert\ACME_Exception;
use Exception;
use stdClass;

class ACMECert extends ACMEv2 {
	private $alternate_chains=array();

	public function register($termsOfServiceAgreed=false,$contacts=array()){
		return $this->_register($termsOfServiceAgreed,$contacts);
	}

	public function registerEAB($termsOfServiceAgreed,$eab_kid,$eab_hmac,$contacts=array()){
		if (!$this->resources) $this->readDirectory();

		$protected=array(
			'alg'=>'HS256',
			'kid'=>$eab_kid,
			'url'=>$this->resources['newAccount']
		);
		$payload=$this->jwk_header['jwk'];

		$protected64=$this->base64url(json_encode($protected,JSON_UNESCAPED_SLASHES));
		$payload64=$this->base64url(json_encode($payload,JSON_UNESCAPED_SLASHES));

		$signature=hash_hmac('sha256',$protected64.'.'.$payload64,$this->base64url_decode($eab_hmac),true);

		return $this->_register($termsOfServiceAgreed,$contacts,array(
			'externalAccountBinding'=>array(
				'protected'=>$protected64,
				'payload'=>$payload64,
				'signature'=>$this->base64url($signature)
			)
		));
	}

	private function _register($termsOfServiceAgreed=false,$contacts=array(),$extra=array()){
		$this->log('Registering account');

		$ret=$this->request('newAccount',array(
			'termsOfServiceAgreed'=>(bool)$termsOfServiceAgreed,
			'contact'=>$this->make_contacts_array($contacts)
		)+$extra);
		$this->log($ret['code']==201?'Account registered':'Account already registered');
		return $ret['body'];
	}

	public function update($contacts=array()){
		$this->log('Updating account');
		$ret=$this->request($this->getAccountID(),array(
			'contact'=>$this->make_contacts_array($contacts)
		));
		$this->log('Account updated');
		return $ret['body'];
	}

	public function getAccount(){
		$ret=parent::getAccount();
		return $ret['body'];
	}

	public function deactivateAccount(){
		$this->log('Deactivating account');
		$ret=$this->deactivate($this->getAccountID());
		$this->log('Account deactivated');
		return $ret;
	}

	public function deactivate($url){
		$this->log('Deactivating resource: '.$url);
		$ret=$this->request($url,array('status'=>'deactivated'));
		$this->log('Resource deactivated');
		return $ret['body'];
	}

	public function getTermsURL(){
		if (!$this->resources) $this->readDirectory();
		if (!isset($this->resources['meta']['termsOfService'])){
			throw new Exception('Failed to get Terms Of Service URL');
		}
		return $this->resources['meta']['termsOfService'];
	}

	public function getCAAIdentities(){
		if (!$this->resources) $this->readDirectory();
		if (!isset($this->resources['meta']['caaIdentities'])){
			throw new Exception('Failed to get CAA Identities');
		}
		return $this->resources['meta']['caaIdentities'];
	}

	public function keyChange($new_account_key_pem){ // account key roll-over
		$ac2=new ACMEv2();
		$ac2->loadAccountKey($new_account_key_pem);
		$account=$this->getAccountID();
		$ac2->resources=$this->resources;

		$this->log('Account Key Roll-Over');

		$ret=$this->request('keyChange',
			$ac2->jws_encapsulate('keyChange',array(
				'account'=>$account,
				'oldKey'=>$this->jwk_header['jwk']
			),true)
		);
		$this->log('Account Key Roll-Over successful');

		$this->loadAccountKey($new_account_key_pem);
		return $ret['body'];
	}

	public function revoke($pem){
		if (false===($res=openssl_x509_read($pem))){
			throw new Exception('Could not load certificate: '.$pem.' ('.$this->get_openssl_error().')');
		}
		if (false===(openssl_x509_export($res,$certificate))){
			throw new Exception('Could not export certificate: '.$pem.' ('.$this->get_openssl_error().')');
		}

		$this->log('Revoking certificate');
		$this->request('revokeCert',array(
			'certificate'=>$this->base64url($this->pem2der($certificate))
		));
		$this->log('Certificate revoked');
	}

	public function getCertificateChain($pem,$domain_config,$callback,$settings=array()){
		$settings=$this->parseSettings($settings);

		$domain_config=array_change_key_case($domain_config,CASE_LOWER);
		$domains=array_keys($domain_config);
		$authz_deactivated=false;

		$this->getAccountID(); // get account info upfront to avoid mixed up logging order

		// === Order ===
		$this->log('Creating Order');
		$ret=$this->request('newOrder',$this->makeOrder($domains,$settings));
		$order=$ret['body'];
		$order_location=$ret['headers']['location'];
		$this->log('Order created: '.$order_location);

		// === Authorization ===
		if ($order['status']==='ready' && $settings['authz_reuse']) {
			$this->log('All authorizations already valid, skipping validation altogether');
		}else{
			$groups=array();
			$auth_count=count($order['authorizations']);

			foreach($order['authorizations'] as $idx=>$auth_url){
				$this->log('Fetching authorization '.($idx+1).' of '.$auth_count);
				$ret=$this->request($auth_url,'');
				$authorization=$ret['body'];

				// wildcard authorization identifiers have no leading *.
				$domain=( // get domain and add leading *. if wildcard is used
					isset($authorization['wildcard']) &&
					$authorization['wildcard'] ?
					'*.':''
				).$authorization['identifier']['value'];

				if ($authorization['status']==='valid') {
					if ($settings['authz_reuse']) {
						$this->log('Authorization of '.$domain.' already valid, skipping validation');
					}else{
						$this->log('Authorization of '.$domain.' already valid, deactivating authorization');
						$this->deactivate($auth_url);
						$authz_deactivated=true;
					}
					continue;
				}

				// groups are used to be able to set more than one TXT Record for one subdomain
				// when using dns-01 before firing the validation to avoid DNS caching problem
				$groups[
					$domain_config[$domain]['challenge'].
					'|'.
					(($settings['group'])?ltrim($domain,'*.'):$domain)
				][$domain]=array($auth_url,$authorization);
			}

			if ($authz_deactivated){
				$this->log('Restarting Order after deactivating already valid authorizations');
				$settings['authz_reuse']=true;
				return $this->getCertificateChain($pem,$domain_config,$callback,$settings);
			}

			// make sure dns-01 comes last to avoid DNS problems for other challenges
			krsort($groups);

			foreach($groups as $group){
				$pending_challenges=array();

				try { // make sure that pending challenges are cleaned up in case of failure
					foreach($group as $domain=>$arr){
						list($auth_url,$authorization)=$arr;

						$config=$domain_config[$domain];
						$type=$config['challenge'];

						$challenge=$this->parse_challenges($authorization,$type,$challenge_url);

						$opts=array(
							'domain'=>$domain,
							'config'=>$config
						);
						list($opts['key'],$opts['value'])=$challenge;

						$this->log('Triggering challenge callback for '.$domain.' using '.$type);
						$remove_cb=$callback($opts);

						$pending_challenges[]=array($remove_cb,$opts,$challenge_url,$auth_url);
					}

					foreach($pending_challenges as $arr){
						list($remove_cb,$opts,$challenge_url,$auth_url)=$arr;
						$this->log('Notifying server for validation of '.$opts['domain']);
						$this->request($challenge_url,new stdClass);

						$this->log('Waiting for server challenge validation');
						sleep(1);

						if (!$this->poll('pending',$auth_url,$body)) {
							$this->log('Validation failed: '.$opts['domain']);

							$error=$body['challenges'][0]['error'];
							throw $this->create_ACME_Exception(
								$error['type'],
								'Challenge validation failed: '.$error['detail']
							);
						}else{
							$this->log('Validation successful: '.$opts['domain']);
						}
					}

				}finally{ // cleanup pending challenges
					foreach($pending_challenges as $arr){
						list($remove_cb,$opts)=$arr;
						if ($remove_cb) {
							$this->log('Triggering remove callback for '.$opts['domain']);
							$remove_cb($opts);
						}
					}
				}
			}
		}

		$this->log('Checking order status');
		if (!$this->poll('pending',$order_location,$order,'ready')){
			throw new Exception('Order did not reach "ready" status');
		}
		$this->log('Order is ready for finalization');

		// autodetect if Private Key or CSR is used
		if ($key=openssl_pkey_get_private($pem)){ // Private Key detected
			if (PHP_MAJOR_VERSION<8) openssl_free_key($key);
			$this->log('Generating CSR');
			$csr=$this->generateCSR($pem,$domains);
		}elseif(openssl_csr_get_subject($pem)){ // CSR detected
			$this->log('Using provided CSR');
			if (0===strpos($pem,'file://')) {
				$csr=file_get_contents(substr($pem,7));
				if (false===$csr) {
					throw new Exception('Failed to read CSR from '.$pem.' ('.$this->get_openssl_error().')');
				}
			}else{
				$csr=$pem;
			}
		}else{
			throw new Exception('Could not load Private Key or CSR ('.$this->get_openssl_error().'): '.$pem);
		}

		$this->log('Finalizing Order');

		$ret=$this->request($order['finalize'],array(
			'csr'=>$this->base64url($this->pem2der($csr))
		));
		$ret=$ret['body'];

		if (isset($ret['certificate'])) {
			return $this->request_certificate($ret);
		}

		if ($this->poll('processing',$order_location,$ret)) {
			return $this->request_certificate($ret);
		}

		throw new Exception('Order failed');
	}

	public function getCertificateChains($pem,$domain_config,$callback,$settings=array()){
		$default_chain=$this->getCertificateChain($pem,$domain_config,$callback,$settings);

		$out=array();
		$out[$this->getTopIssuerCN($default_chain)]=$default_chain;

		foreach($this->alternate_chains as $link){
			$chain=$this->request_certificate(array('certificate'=>$link),true);
			$out[$this->getTopIssuerCN($chain)]=$chain;
		}

		$this->log('Received '.count($out).' chain(s): '.implode(', ',array_keys($out)));
		return $out;
	}

	public function generateCSR($domain_key_pem,$domains){
		if (false===($domain_key=openssl_pkey_get_private($domain_key_pem))){
			throw new Exception('Could not load domain key: '.$domain_key_pem.' ('.$this->get_openssl_error().')');
		}

		$fn=$this->tmp_ssl_cnf($domains);
		$cn=reset($domains);
		$dn=array();
		if (!filter_var($cn,FILTER_VALIDATE_IP) && strlen($cn)<=64){
			$dn['commonName']=$cn;
		}
		$csr=openssl_csr_new($dn,$domain_key,array(
			'config'=>$fn,
			'req_extensions'=>'SAN',
			'digest_alg'=>'sha512'
		));
		unlink($fn);
		if (PHP_MAJOR_VERSION<8) openssl_free_key($domain_key);

		if (false===$csr) {
			throw new Exception('Could not generate CSR ! ('.$this->get_openssl_error().')');
		}
		if (false===openssl_csr_export($csr,$out)){
			throw new Exception('Could not export CSR ! ('.$this->get_openssl_error().')');
		}

		return $out;
	}

	private function generateKey($opts){
		$fn=$this->tmp_ssl_cnf();
		$config=array('config'=>$fn)+$opts;
		if (false===($key=openssl_pkey_new($config))){
			throw new Exception('Could not generate new private key ! ('.$this->get_openssl_error().')');
		}
		if (false===openssl_pkey_export($key,$pem,null,$config)){
			throw new Exception('Could not export private key ! ('.$this->get_openssl_error().')');
		}
		unlink($fn);
		if (PHP_MAJOR_VERSION<8) openssl_free_key($key);
		return $pem;
	}

	public function generateRSAKey($bits=2048){
		return $this->generateKey(array(
			'private_key_bits'=>(int)$bits,
			'private_key_type'=>OPENSSL_KEYTYPE_RSA
		));
	}

	public function generateECKey($curve_name='P-384'){
		if (version_compare(PHP_VERSION,'7.1.0')<0) throw new Exception('PHP >= 7.1.0 required for EC keys !');
		$map=array('P-256'=>'prime256v1','P-384'=>'secp384r1','P-521'=>'secp521r1');
		if (isset($map[$curve_name])) $curve_name=$map[$curve_name];
		return $this->generateKey(array(
			'curve_name'=>$curve_name,
			'private_key_type'=>OPENSSL_KEYTYPE_EC
		));
	}

	public function parseCertificate($cert_pem){
		if (false===($ret=openssl_x509_read($cert_pem))) {
			throw new Exception('Could not load certificate: '.$cert_pem.' ('.$this->get_openssl_error().')');
		}
		if (!is_array($ret=openssl_x509_parse($ret,true))) {
			throw new Exception('Could not parse certificate ('.$this->get_openssl_error().')');
		}
		return $ret;
	}

	public function getSAN($pem){
		$ret=$this->parseCertificate($pem);
		if (!isset($ret['extensions']['subjectAltName'])){
			throw new Exception('No Subject Alternative Name (SAN) found in certificate');
		}
		$out=array();
		foreach(explode(',',$ret['extensions']['subjectAltName']) as $line){
			list($type,$name)=array_map('trim',explode(':',$line,2));
			if ($type==='DNS' || $type==='IP Address'){
				$out[]=$name;
			}
		}
		return $out;
	}

	public function getRemainingDays($cert_pem){
		$ret=$this->parseCertificate($cert_pem);
		return ($ret['validTo_time_t']-time())/86400;
	}

	public function getRemainingPercent($cert_pem){
		$ret=$this->parseCertificate($cert_pem);
		$total=$ret['validTo_time_t']-$ret['validFrom_time_t'];
		$used=time()-$ret['validFrom_time_t'];
		return (1-max(0,min(1,$used/$total)))*100;
	}

	public function generateALPNCertificate($domain_key_pem,$domain,$token){
		$domains=array($domain);
		$csr=$this->generateCSR($domain_key_pem,$domains);

		$fn=$this->tmp_ssl_cnf($domains,'1.3.6.1.5.5.7.1.31=critical,DER:0420'.$token."\n");
		$config=array(
			'config'=>$fn,
			'x509_extensions'=>'SAN',
			'digest_alg'=>'sha512'
		);
		$cert=openssl_csr_sign($csr,null,$domain_key_pem,1,$config);
		unlink($fn);
		if (false===$cert) {
			throw new Exception('Could not generate self signed certificate ! ('.$this->get_openssl_error().')');
		}
		if (false===openssl_x509_export($cert,$out)){
			throw new Exception('Could not export self signed certificate ! ('.$this->get_openssl_error().')');
		}
		return $out;
	}

	public function getProfiles(){
		if (!$this->resources) $this->readDirectory();
		if (
			!isset($this->resources['meta']['profiles']) ||
			!is_array($this->resources['meta']['profiles']))
		{
			throw new Exception('certificate profiles not supported by CA');
		}
		return $this->resources['meta']['profiles'];
	}

	private function requireARI(){
		if (!$this->resources) $this->readDirectory();
		if (!isset($this->resources['renewalInfo'])) throw new Exception('ARI not supported by CA');
	}

	public function getARI($pem,&$ari_cert_id=null){
		$ari_cert_id=null;

		$id=$this->getARICertID($pem);
		$this->requireARI();

		$this->log('Requesting ACME Renewal Information');
		$ret=$this->http_request($this->resources['renewalInfo'].'/'.$id);
		$this->delay_until=null;

		if (!is_array($ret['body']['suggestedWindow'])) throw new Exception('ARI suggestedWindow not present');

		$sw=&$ret['body']['suggestedWindow'];

		if (!isset($sw['start'])) throw new Exception('ARI suggestedWindow start not present');
		if (!isset($sw['end'])) throw new Exception('ARI suggestedWindow end not present');

		$sw=array_map(array($this,'parseDate'),$sw);

		$out=$ret['body'];

		if (isset($out['explanationURL'])){
			if (trim($out['explanationURL'])===''){
				unset($out['explanationURL']);
			}
		}

		if (isset($ret['headers']['retry-after'])){
			$tmp=$this->parseRetryAfterHeader($ret['headers']['retry-after']);
			if ($tmp>0){
				$out['retry_after']=$tmp;
			}
		}

		$out['ari_cert_id']=$id;
		$ari_cert_id=$id;
		return $out;
	}

	private function getARICertID($pem){
		if (version_compare(PHP_VERSION,'7.1.2','<')){
			throw new Exception('PHP Version >= 7.1.2 required for ARI'); // serialNumberHex - https://github.com/php/php-src/pull/1755
		}

		$ret=$this->parseCertificate($pem);

		if (!isset($ret['extensions']['authorityKeyIdentifier'])) {
			throw new Exception('authorityKeyIdentifier missing');
		}

		$aki=trim($ret['extensions']['authorityKeyIdentifier']);
		if (stripos($aki,'keyid')===0) $aki=substr($aki,5);
		$aki=hex2bin(str_replace(':','',$aki));
		if (!$aki) throw new Exception('Failed to parse authorityKeyIdentifier');

		if (!isset($ret['serialNumberHex'])) {
			throw new Exception('serialNumberHex missing');
		}
		$ser=hex2bin(trim($ret['serialNumberHex']));
		if (!$ser) throw new Exception('Failed to parse serialNumberHex');
		if (ord($ser[0]) & 0x80) $ser="\x00".$ser;

		return $this->base64url($aki).'.'.$this->base64url($ser);
	}

	private function parseDate($str){
		$ret=strtotime(preg_replace('/(\.\d\d)\d+/','$1',$str));
		if ($ret===false) throw new Exception('Failed to parse date: '.$str);
		return $ret;
	}

	private function parseSettings($opts){
		// authz_reuse: backwards compatibility to ACMECert v3.1.2 or older
		if (!is_array($opts)) $opts=array('authz_reuse'=>(bool)$opts);
		if (!isset($opts['authz_reuse'])) $opts['authz_reuse']=true;
		if (!isset($opts['group'])) $opts['group']=true;

		$diff=array_diff_key(
			$opts,
			array_flip(array('authz_reuse','notAfter','notBefore','replaces','profile','group'))
		);

		if (!empty($diff)){
			throw new Exception('getCertificateChain(s): Invalid option "'.key($diff).'"');
		}

		return $opts;
	}

	private function setRFC3339Date(&$out,$key,$opts){
		if (isset($opts[$key])){
			$out[$key]=is_string($opts[$key])?
				$opts[$key]:
				date(DATE_RFC3339,$opts[$key]);
		}
	}

	private function makeOrder($domains,$opts){
		$order=array(
			'identifiers'=>array_map(
				function($domain){
					if (filter_var($domain,FILTER_VALIDATE_IP)){
						return array('type'=>'ip','value'=>$domain);
					}else{
						return array('type'=>'dns','value'=>$domain);
					}
				},
				$domains
			)
		);
		$this->setRFC3339Date($order,'notAfter',$opts);
		$this->setRFC3339Date($order,'notBefore',$opts);

		if (isset($opts['replaces'])) { // ARI
			$this->requireARI();
			$order['replaces']=$opts['replaces'];
			$this->log('Replacing Certificate: '.$opts['replaces']);
		}

		if (isset($opts['profile'])) { // certificate profiles
			$profiles=$this->getProfiles();

			if (!isset($profiles[$opts['profile']])) {
				throw new Exception('certificate profile "'.$opts['profile'].'" not supported by CA');
			}

			$order['profile']=$opts['profile'];
			$this->log('Selected certificate profile: '.$opts['profile']);
		}

		return $order;
	}

	private function parse_challenges($authorization,$type,&$url){
		foreach($authorization['challenges'] as $challenge){
			if ($challenge['type']!=$type) continue;

			$url=$challenge['url'];

			switch($challenge['type']){
				case 'dns-01':
					return array(
						'_acme-challenge.'.$authorization['identifier']['value'],
						$this->base64url(hash('sha256',$this->keyAuthorization($challenge['token']),true))
					);
				break;
				case 'http-01':
					return array(
						'/.well-known/acme-challenge/'.$challenge['token'],
						$this->keyAuthorization($challenge['token'])
					);
				break;
				case 'tls-alpn-01':
					return array(null,hash('sha256',$this->keyAuthorization($challenge['token'])));
				break;
			}
		}
		throw new Exception(
			'Challenge type: "'.$type.'" not available, for this challenge use '.
			implode(' or ',array_map(
				function($a){
					return '"'.$a['type'].'"';
				},
				$authorization['challenges']
			))
		);
	}

	private function poll($initial,$type,&$ret,$success='valid'){
		$max_tries=10; // ~ 5 minutes
		for($i=0;$i<$max_tries;$i++){
			$ret=$this->request($type);
			$ret=$ret['body'];
			if ($ret['status']!==$initial) return $ret['status']===$success;
			$s=pow(2,min($i,6));
			if ($i!==$max_tries-1){
				$this->log('Retrying in '.($s).'s');
				sleep($s);
			}
		}
		throw new Exception('Aborted after '.$max_tries.' tries');
	}

	private function request_certificate($ret,$alternate=false){
		$this->log('Requesting '.($alternate?'alternate':'default').' certificate-chain');
		$ret=$this->request($ret['certificate'],'');
		if ($ret['headers']['content-type']!=='application/pem-certificate-chain'){
			throw new Exception('Unexpected content-type: '.$ret['headers']['content-type']);
		}

		$chain=array();
		foreach($this->splitChain($ret['body']) as $cert){
			$info=$this->parseCertificate($cert);
			$chain[]='['.$info['issuer']['CN'].']';
		}

		if (!$alternate) {
			if (isset($ret['headers']['link']['alternate'])){
				$this->alternate_chains=$ret['headers']['link']['alternate'];
			}else{
				$this->alternate_chains=array();
			}
		}

		$this->log(($alternate?'Alternate':'Default').' certificate-chain retrieved: '.implode(' -> ',array_reverse($chain,true)));
		return $ret['body'];
	}

	private function tmp_ssl_cnf($domains=null,$extension=''){
		if (false===($fn=tempnam(sys_get_temp_dir(), "CNF_"))){
			throw new Exception('Failed to create temp file !');
		}
		if (false===@file_put_contents($fn,
			'HOME = .'."\n".
			'RANDFILE=$ENV::HOME/.rnd'."\n".
			'[v3_ca]'."\n".
			'[req]'."\n".
			'default_bits=2048'."\n".
			($domains?
				'distinguished_name=req_distinguished_name'."\n".
				'[req_distinguished_name]'."\n".
				'[v3_req]'."\n".
				'[SAN]'."\n".
				'subjectAltName='.
				implode(',',array_map(function($domain){
					if (filter_var($domain,FILTER_VALIDATE_IP)){
						return 'IP:'.$domain;
					}else{
						return 'DNS:'.$domain;
					}

				},$domains))."\n"
			:
				''
			).$extension
		)){
			throw new Exception('Failed to write tmp file: '.$fn);
		}
		return $fn;
	}

	private function pem2der($pem) {
		return base64_decode(implode('',array_slice(
			array_map('trim',explode("\n",trim($pem))),1,-1
		)));
	}

	private function make_contacts_array($contacts){
		if (!is_array($contacts)) {
			$contacts=$contacts?array($contacts):array();
		}
		return array_map(function($contact){
			return 'mailto:'.$contact;
		},$contacts);
	}

	private function getTopIssuerCN($chain){
		$tmp=$this->splitChain($chain);
		$ret=$this->parseCertificate(end($tmp));
		return $ret['issuer']['CN'];
	}

	public function splitChain($chain){
		$delim='-----END CERTIFICATE-----';
		return array_map(function($item)use($delim){
			return trim($item.$delim);
		},array_filter(explode($delim,$chain),function($item){
			return strpos($item,'-----BEGIN CERTIFICATE-----')!==false;
		}));
	}
}

}

namespace {
// Build template: bundled with the pinned, unmodified ACMECert sources.
ini_set('display_errors', '0');
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
const STORAGE_GUARD = "<?php http_response_code(404); exit; ?>\n";
const COOKIE_NAME = 'ssl_assistant_session';
const ACCESS_DAYS = 30;

function reply(int $status, array $data): void {
    http_response_code($status);
    echo json_encode(['helper' => 'freessl', 'version' => 2] + $data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
function fail(int $status, string $message): void { reply($status, ['ok' => false, 'message' => $message]); }
function ordinary(string $path): void {
    clearstatcache(true, $path);
    if (is_link($path) || (file_exists($path) && !is_file($path))) fail(409, '运行文件路径异常，请在主机面板检查。');
}
function guardedRead(string $path): string {
    ordinary($path);
    $text = @file_get_contents($path);
    if (!is_string($text) || !str_starts_with($text, STORAGE_GUARD)) fail(500, '运行数据格式不正确，请在主机面板检查。');
    return substr($text, strlen(STORAGE_GUARD));
}
function guardedWrite(string $path, string $text): void {
    ordinary($path);
    $temporary = dirname($path) . '/ssl-tmp-' . bin2hex(random_bytes(12)) . '.php';
    $handle = @fopen($temporary, 'x');
    if (!$handle) fail(500, 'PHP 无权保存运行数据，请检查网站目录写入权限。');
    @chmod($temporary, 0600);
    $data = STORAGE_GUARD . $text;
    $written = fwrite($handle, $data) === strlen($data) && fflush($handle);
    fclose($handle);
    ordinary($path);
    if (!$written || !@rename($temporary, $path)) { @unlink($temporary); fail(500, '运行数据未完整保存，请检查权限后重试。'); }
}
function loadConfig(string $path): array {
    ordinary($path);
    if (!file_exists($path)) return [];
    try { $data = json_decode(guardedRead($path), true, 32, JSON_THROW_ON_ERROR); }
    catch (Throwable $error) { fail(500, '授权数据格式不正确，请在主机面板检查。'); }
    if (!is_array($data)) fail(500, '授权数据格式不正确。');
    return $data;
}
function saveConfig(string $path, array $data): void { guardedWrite($path, json_encode($data, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)); }
function lockState(string $root) {
    $path = $root . '/ssl-helper.lock.php'; ordinary($path);
    if (!file_exists($path)) { $h = @fopen($path, 'x'); if ($h) { fwrite($h, STORAGE_GUARD); fclose($h); @chmod($path, 0600); } }
    $lock = @fopen($path, 'r+');
    if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) fail(409, '另一个操作正在进行，请稍后再试。');
    return $lock;
}
function secureRequest(): bool { return ($_SERVER['HTTPS'] ?? '') === 'on' || ($_SERVER['HTTPS'] ?? '') === '1'; }
function setSessionCookie(string $token, int $expiry): void {
    setcookie(COOKIE_NAME, $token, ['expires' => $expiry, 'path' => '/', 'secure' => secureRequest(), 'httponly' => true, 'samesite' => 'Strict']);
}
function sessionToken(): string {
    $token = $_COOKIE[COOKIE_NAME] ?? '';
    return is_string($token) ? $token : '';
}
function authenticated(array $config): bool {
    $token = sessionToken();
    return isset($config['password_hash']) && preg_match('/\A[A-Za-z0-9_-]{43}\z/D', $token) === 1
        && ($config['sessions'][hash('sha256', $token)] ?? 0) > time();
}
function startLogin(array &$config): void {
    $config['sessions'] = array_filter($config['sessions'] ?? [], static fn($expiry) => is_int($expiry) && $expiry > time());
    asort($config['sessions']);
    while (count($config['sessions']) >= 10) array_shift($config['sessions']);
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $expiry = time() + ACCESS_DAYS * 86400;
    $config['sessions'][hash('sha256', $token)] = $expiry;
    setSessionCookie($token, $expiry);
}
function chosenPassword(array $body): string {
    $password = $body['password'] ?? null;
    if (!is_string($password) || str_contains($password, "\0") || preg_match_all('/./us', $password) < 8) fail(400, '密码至少需要 8 个字符。');
    if (strlen($password) > 72) fail(400, '密码太长，请缩短后重试。');
    if (!isset($body['confirmPassword']) || !is_string($body['confirmPassword']) || !hash_equals($password, $body['confirmPassword'])) fail(400, '两次输入的密码不一致。');
    return $password;
}
function sameOrigin(): void {
    $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '';
    if ($site !== '' && $site !== 'same-origin') fail(403, '只能从当前网站的证书助手提交。');
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        $expected = (secureRequest() ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? '');
        if (strtolower(rtrim($origin, '/')) !== strtolower($expected)) fail(403, '请求来源与当前网站不一致。');
    }
}
function inputBody(): array {
    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) fail(415, '请求必须使用 JSON。');
    if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 32768) fail(413, '请求过大。');
    $raw = file_get_contents('php://input', false, null, 0, 32769);
    if ($raw === false || strlen($raw) > 32768) fail(413, '请求过大。');
    try { $body = json_decode($raw, true, 16, JSON_THROW_ON_ERROR); } catch (Throwable $error) { fail(400, '请求格式无效。'); }
    if (!is_array($body)) fail(400, '请求格式无效。');
    return $body;
}
function environment(array $body): string {
    $env = $body['environment'] ?? 'production';
    if ($env !== 'production') fail(400, '仅支持正式证书签发。');
    return $env;
}
function domains(array $input, string $method = 'http-01'): array {
    if (count($input) < 1 || count($input) > 100) fail(400, '一张证书需要 1 到 100 个域名。');
    $out = [];
    foreach ($input as $value) {
        if (!is_string($value)) fail(400, '域名格式不正确。');
        $value = strtolower($value);
        $check = $value;
        if (str_starts_with($value, '*.')) {
            if ($method !== 'dns-01') fail(400, '泛域名需要选择 DNS 验证。');
            $check = substr($value, 2);
        }
        if (strlen($value) > 253 || strpos($value, '.') === false || filter_var($value, FILTER_VALIDATE_IP)) fail(400, '请填写完整域名。');
        foreach (explode('.', $check) as $label) if (!preg_match('/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/D', $label)) fail(400, '域名格式不正确。');
        $out[$value] = true;
    }
    $result = array_keys($out); sort($result); return $result;
}
function placeFiles(string $root, array $files): array {
    if (count($files) < 1 || count($files) > 100) fail(400, '一次只能放置 1 到 100 个验证文件。');
    $validated = [];
    foreach ($files as $file) {
        if (!is_array($file) || count($file) !== 2 || !isset($file['name'], $file['content']) || !is_string($file['name']) || !is_string($file['content'])) fail(400, '验证文件字段无效。');
        $name = $file['name']; $content = $file['content'];
        if (!preg_match('/\A[A-Za-z0-9_-]{16,128}\z/D', $name) || !preg_match('/\A[A-Za-z0-9_-]{16,128}\.[A-Za-z0-9_-]{43}\z/D', $content) || !str_starts_with($content, $name . '.')) fail(400, '只能写入合法的 ACME 验证文件。');
        if (isset($validated[$name]) && $validated[$name] !== $content) fail(409, '验证文件名冲突。');
        $validated[$name] = $content;
    }
    $directory = $root;
    foreach (['.well-known', 'acme-challenge'] as $part) {
        $directory .= '/' . $part;
        if (is_link($directory) || (file_exists($directory) && !is_dir($directory))) fail(409, '验证目录不是普通目录，请在主机面板检查。');
        if (!is_dir($directory) && !@mkdir($directory, 0755)) fail(500, 'PHP 无法在网站根目录创建验证文件夹。请检查目录权限，或改用 DNS 验证。');
        if (realpath($directory) !== $directory) fail(409, '验证目录路径异常。');
    }
    $created = [];
    foreach ($validated as $name => $content) {
        $destination = $directory . '/' . $name; ordinary($destination);
        if (is_file($destination)) {
            if (@file_get_contents($destination) === $content) continue;
            fail(409, '同名验证文件已存在且内容不同，请重新申请。');
        }
        $handle = @fopen($destination, 'x');
        if (!$handle) fail(500, '验证文件创建失败，请检查权限。');
        $written = fwrite($handle, $content) === strlen($content) && fflush($handle); fclose($handle);
        if (!$written) { @unlink($destination); fail(500, '验证文件未完整写入。'); }
        @chmod($destination, 0644); $created[$destination] = $content;
    }
    return $created;
}

// Isolated transport adapter: official hosts only, TLS verification, no redirects,
// bounded requests. The upstream transport otherwise follows arbitrary redirects.
function assistantFetchRaw(string $url, $data): array {
    $method = $data === false ? 'HEAD' : ($data === null ? 'GET' : 'POST');
    $requestHeaders = $method === 'POST' ? ['Content-Type: application/jose+json'] : [];
    if (extension_loaded('curl')) {
        $headers = []; $handle = curl_init($url);
        curl_setopt_array($handle, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 25, CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CUSTOMREQUEST => $method, CURLOPT_NOBODY => $method === 'HEAD',
            CURLOPT_HTTPHEADER => $requestHeaders, CURLOPT_USERAGENT => 'freessl/1.0',
            CURLOPT_HEADERFUNCTION => static function ($handle, $line) use (&$headers) { $headers[] = $line; return strlen($line); }]);
        if ($method === 'POST') curl_setopt($handle, CURLOPT_POSTFIELDS, $data);
        $body = curl_exec($handle); $status = curl_getinfo($handle, CURLINFO_RESPONSE_CODE); curl_close($handle);
        if ($body === false) throw new RuntimeException('无法连接官方证书服务，请检查服务器网络和 CA 信任配置。');
    } else {
        $options = ['http' => ['method' => $method, 'header' => $requestHeaders, 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 25], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]];
        if ($method === 'POST') $options['http']['content'] = $data;
        $body = @file_get_contents($url, false, stream_context_create($options));
        $headers = PHP_VERSION_ID >= 80400 ? http_get_last_response_headers() : ($http_response_header ?? []);
        $status = 0;
        foreach ($headers ?? [] as $line) if (preg_match('/^HTTP\/\S+\s+(\d{3})/', $line, $match)) $status = (int) $match[1];
        if ($body === false) throw new RuntimeException('无法连接官方证书服务，请检查服务器网络和 CA 信任配置。');
    }
    $parsed = [];
    foreach ($headers as $line) {
        if (str_starts_with($line, 'HTTP/')) { $parsed = []; continue; }
        $pair = explode(':', $line, 2);
        if (count($pair) === 2) $parsed[strtolower(trim($pair[0]))] = trim($pair[1]);
    }
    return ['code' => (string) $status, 'headers' => $parsed, 'body' => $body];
}
class AssistantACME extends \skoerfgen\ACMECert\ACMECert {
    private float $deadline;
    private string $officialHost;
    public function __construct(string $environment) {
        if ($environment !== 'production') throw new RuntimeException('仅支持正式证书签发。');
        $this->officialHost = 'acme-v02.api.letsencrypt.org';
        parent::__construct('https://' . $this->officialHost . '/directory');
        $this->deadline = microtime(true) + 210; $this->setLogger(false);
    }
    // The upstream all-in-one callback is synchronous. This small adapter reuses
    // its signing, CSR and transport for RFC 8555 orders resumed across requests.
    public function beginManual(array $domains, string $method): array {
        $this->getAccountID();
        $ret = $this->request('newOrder', ['identifiers' => array_map(static fn($domain) => ['type' => 'dns', 'value' => $domain], $domains)]);
        $order = $ret['body']; $url = $ret['headers']['location'] ?? '';
        if (!is_array($order) || $url === '') throw new RuntimeException('订单无效。');
        $resources = [];
        foreach ($order['authorizations'] as $authorizationURL) {
            $authorization = $this->request($authorizationURL)['body'];
            if (($authorization['status'] ?? '') === 'valid') continue;
            $domain = $authorization['identifier']['value'];
            $displayDomain = ($authorization['wildcard'] ?? false) ? '*.' . $domain : $domain;
            if (!in_array($displayDomain, $domains, true)) throw new RuntimeException('验证域名无效。');
            $found = false;
            foreach ($authorization['challenges'] as $challenge) {
                if ($challenge['type'] !== $method) continue;
                $found = true; $authorizationValue = $this->keyAuthorization($challenge['token']);
                $resources[] = $method === 'http-01'
                    ? ['domain' => $displayDomain, 'name' => $challenge['token'], 'content' => $authorizationValue, 'url' => 'http://' . $domain . '/.well-known/acme-challenge/' . $challenge['token']]
                    : ['domain' => $displayDomain, 'name' => '_acme-challenge.' . $domain, 'content' => $this->base64url(hash('sha256', $authorizationValue, true))];
                break;
            }
            if (!$found) throw new RuntimeException('所选验证方式不可用。');
        }
        return ['orderURL' => $url, 'resources' => $resources];
    }
    private function awaitManual(string $url, string $success): array {
        for ($attempt = 0; $attempt < 80; $attempt++) {
            $data = $this->request($url)['body']; $status = $data['status'] ?? '';
            if ($status === $success || ($success === 'ready' && $status === 'valid')) return $data;
            if (in_array($status, ['invalid', 'expired', 'deactivated', 'revoked'], true)) throw new AssistantInvalidOrder();
            usleep(1000000);
        }
        throw new RuntimeException('等待验证超时。');
    }
    public function finishManual(array $pending, string $privateKey): string {
        $this->getAccountID();
        $order = $this->request($pending['orderURL'])['body'];
        if (($order['status'] ?? '') === 'invalid') throw new AssistantInvalidOrder();
        if (($order['status'] ?? '') === 'pending') {
            foreach ($order['authorizations'] as $url) {
                $auth = $this->request($url)['body'];
                if (($auth['status'] ?? '') === 'valid') continue;
                if (in_array($auth['status'] ?? '', ['invalid', 'expired', 'revoked', 'deactivated'], true)) throw new AssistantInvalidOrder();
                $challengeURL = null;
                foreach ($auth['challenges'] as $challenge) if ($challenge['type'] === $pending['method']) { $challengeURL = $challenge['url']; break; }
                if (!$challengeURL) throw new RuntimeException('验证方式无效。');
                $this->request($challengeURL, new \stdClass()); $this->awaitManual($url, 'valid');
            }
            $order = $this->awaitManual($pending['orderURL'], 'ready');
        }
        if (($order['status'] ?? '') === 'ready') {
            $csr = $this->generateCSR($privateKey, $pending['domains']);
            $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $csr), true);
            if ($der === false) throw new RuntimeException('CSR 无效。');
            $order = $this->request($order['finalize'], ['csr' => $this->base64url($der)])['body'];
        }
        if (($order['status'] ?? '') !== 'valid') $order = $this->awaitManual($pending['orderURL'], 'valid');
        if (!isset($order['certificate'])) throw new RuntimeException('证书尚未生成。');
        return $this->request($order['certificate'])['body'];
    }
    protected function http_request($url, $data = null) {
        $parts = parse_url($url);
        if (!$parts || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') !== $this->officialHost || isset($parts['port']) || isset($parts['user']) || isset($parts['pass'])) throw new RuntimeException('已阻止连接到非官方证书接口。');
        if (microtime(true) > $this->deadline) throw new RuntimeException('签发等待超时。稍后打开页面检查结果，或改用本地引导。');
        $ret = assistantFetchRaw($url, $data);
        if (isset($ret['headers']['replay-nonce'])) $this->nonce = $ret['headers']['replay-nonce'];
        $type = strtolower(explode(';', $ret['headers']['content-type'] ?? '')[0]);
        if (in_array($type, ['application/json', 'application/problem+json'], true)) {
            $ret['body'] = json_decode($ret['body'], true, 64, JSON_THROW_ON_ERROR);
            $problem = $ret['body']['error'] ?? ($type === 'application/problem+json' ? $ret['body'] : null);
            if (is_array($problem)) throw new \skoerfgen\ACMECert\ACME_Exception($problem['type'] ?? 'acme:error', $problem['detail'] ?? '官方证书服务拒绝了本次操作。');
        }
        if ((int) $ret['code'] < 200 || (int) $ret['code'] >= 300) throw new RuntimeException('官方证书服务返回 HTTP ' . $ret['code'] . '，请稍后重试。');
        return $ret;
    }
}
class AssistantInvalidOrder extends \RuntimeException {}
function records(array $config): array {
    $records = $config['records'] ?? [];
    foreach ($config['pending'] ?? [] as $id => $pending) {
        $records[$id] = ($records[$id] ?? []) + array_intersect_key($pending, array_flip(['id', 'domains', 'environment', 'keyAlgorithm', 'method', 'target']));
        $records[$id]['pending'] = true;
    }
    return array_values(array_filter($records, static fn($record) => ($record['environment'] ?? 'production') === 'production'));
}
function pendingData(array $pending): array {
    return ['ok' => true, 'pending' => true, 'record' => array_intersect_key($pending, array_flip(['id', 'domains', 'environment', 'keyAlgorithm', 'method', 'target'])), 'resources' => $pending['resources']];
}
function resultData(array $record, string $root, bool $reused = false): array {
    return ['ok' => true, 'record' => $record, 'certificate' => guardedRead($root . '/' . $record['certificateFile']),
        'privateKey' => guardedRead($root . '/' . $record['privateKeyFile']), 'reused' => $reused];
}

$root = realpath(__DIR__); $documentRoot = realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
if (!$root || !$documentRoot || !is_dir($documentRoot)
    || ($root !== $documentRoot && !str_starts_with($root, rtrim($documentRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR))) {
    fail(409, '请将 freessl.html 和 freessl.php 放在同一个网站目录内。可以使用网站根目录，也可以使用它下面的子目录。');
}
$configPath = $root . '/ssl-helper.config.php';
$passwordPath = $root . '/freessl-password.php';
$config = loadConfig($configPath); $access = loadConfig($passwordPath);
// Move an existing installation's login fields once. Certificates/accounts stay
// in place; deleting the separate password file can then reset login only.
if (isset($config['password_hash'])) {
    $migrationLock = lockState($root);
    $config = loadConfig($configPath); $access = loadConfig($passwordPath);
    $loginFields = array_flip(['password_hash', 'sessions', 'login_failures', 'login_blocked_until']);
    if (!file_exists($passwordPath) && isset($config['password_hash'])) {
        $access = array_intersect_key($config, $loginFields); saveConfig($passwordPath, $access);
    }
    $config = array_diff_key($config, $loginFields); saveConfig($configPath, $config);
    flock($migrationLock, LOCK_UN); fclose($migrationLock);
}
$configured = isset($access['password_hash']); $signedIn = authenticated($access);
$capable = PHP_VERSION_ID >= 80100 && extension_loaded('openssl') && (extension_loaded('curl') || (bool) ini_get('allow_url_fopen')) && is_writable($root);
$action = $_GET['action'] ?? ''; $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'GET' && $action === 'status') reply(200, ['ok' => true, 'configured' => $configured, 'capable' => $capable, 'authenticated' => $signedIn, 'records' => $signedIn ? records($config) : [], 'agreedTerms' => $signedIn ? ($config['agreedTerms'] ?? []) : [], 'message' => $capable ? '' : '需要 PHP 8.1+、OpenSSL、cURL 或 allow_url_fopen，以及网站目录写入权限。']);
if ($method !== 'POST') fail(405, '不支持这个操作。');
sameOrigin(); $body = inputBody();
if ($action === 'directory') {
    if (!$capable) fail(503, 'PHP 环境不能自动签发，请使用本地引导。');
    try { $ac = new AssistantACME(environment($body)); $terms = $ac->getTermsURL();
        if (parse_url($terms, PHP_URL_SCHEME) !== 'https' || parse_url($terms, PHP_URL_HOST) !== 'letsencrypt.org') throw new RuntimeException();
        reply(200, ['ok' => true, 'terms' => $terms]);
    } catch (Throwable $error) { fail(502, '无法连接官方证书服务，请检查服务器网络和 CA 信任配置。'); }
}
if (!in_array($action, ['set-password', 'login', 'logout', 'write', 'issue', 'renew', 'result', 'complete', 'pending', 'delete'], true)) fail(405, '不支持这个操作。');
if (!in_array($action, ['set-password', 'login', 'logout'], true)) {
    if (!$configured) fail(503, '首次使用，请先设置密码。');
    if (!$signedIn) fail(403, '请先输入密码登录。');
}
// One fixed lock serializes configuration and issuance; never overwrite a symlink.
$lock = lockState($root);
$config = loadConfig($configPath); $access = loadConfig($passwordPath); $configured = isset($access['password_hash']);
if ($action === 'set-password') {
    if ($configured) fail(409, '密码已经设置，请直接登录。');
    if (!$capable) fail(503, 'PHP 环境不能自动签发，请使用本地引导。');
    $password = chosenPassword($body);
    try { $access['password_hash'] = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]); }
    catch (Throwable $error) { fail(500, '密码设置失败，请检查 PHP 环境后重试。'); }
    startLogin($access); saveConfig($passwordPath, $access);
    reply(200, ['ok' => true]);
}
if ($action === 'login') {
    if (!$configured) fail(409, '首次使用，请先设置密码。');
    if (($access['login_blocked_until'] ?? 0) > time()) fail(429, '密码尝试次数过多，请一分钟后再试。');
    $password = $body['password'] ?? '';
    if (!is_string($password) || strlen($password) > 72 || str_contains($password, "\0") || !password_verify($password, $access['password_hash'])) {
        $access['login_failures'] = ($access['login_failures'] ?? 0) + 1;
        if ($access['login_failures'] >= 5) { $access['login_blocked_until'] = time() + 60; $access['login_failures'] = 0; }
        saveConfig($passwordPath, $access); fail(403, '密码不正确，请重试。');
    }
    unset($access['login_failures'], $access['login_blocked_until']);
    startLogin($access); saveConfig($passwordPath, $access); reply(200, ['ok' => true]);
}
if ($action === 'logout') {
    unset($access['sessions'][hash('sha256', sessionToken())]);
    if ($configured) saveConfig($passwordPath, $access);
    setSessionCookie('', time() - 3600); reply(200, ['ok' => true]);
}
if (!authenticated($access)) fail(403, '登录已过期，请重新输入密码。');
$expiry = time() + ACCESS_DAYS * 86400;
$access['sessions'][hash('sha256', sessionToken())] = $expiry;
saveConfig($passwordPath, $access); setSessionCookie(sessionToken(), $expiry);
if ($action === 'write') {
    if (!isset($body['files']) || !is_array($body['files'])) fail(400, '验证文件格式无效。');
    placeFiles($documentRoot, $body['files']); reply(200, ['ok' => true, 'written' => count($body['files'])]);
}
if ($action === 'result') {
    $id = $body['id'] ?? ''; if (!is_string($id) || !isset($config['records'][$id])) fail(404, '没有找到这张证书。');
    environment($config['records'][$id]);
    reply(200, resultData($config['records'][$id], $root));
}
if ($action === 'pending') {
    $id = $body['id'] ?? ''; if (!is_string($id) || !isset($config['pending'][$id])) fail(404, '没有找到待验证的申请。');
    environment($config['pending'][$id]);
    reply(200, pendingData($config['pending'][$id]));
}
if ($action === 'delete') {
    $id = $body['id'] ?? '';
    if (!is_string($id) || preg_match('/\A[0-9a-f]{64}\z/D', $id) !== 1) fail(400, '证书记录编号无效。');
    if (!isset($config['records'][$id]) && !isset($config['pending'][$id])) fail(404, '没有找到这条证书记录。');
    $files = [];
    foreach (['certificateFile', 'privateKeyFile'] as $field) {
        $name = $config['records'][$id][$field] ?? null;
        if ($name === null) continue;
        if (!is_string($name) || preg_match('/\Assl-(?:certificate|private-key)-[0-9a-f]{16}-[0-9a-f]{12}\.php\z/D', $name) !== 1) fail(409, '证书文件记录异常，请在主机面板检查。');
        ordinary($root . '/' . $name);
        $shared = false;
        foreach ($config['records'] ?? [] as $otherId => $other) {
            if ($otherId !== $id && in_array($name, [$other['certificateFile'] ?? null, $other['privateKeyFile'] ?? null], true)) $shared = true;
        }
        if (!$shared) $files[] = $root . '/' . $name;
    }
    unset($config['records'][$id], $config['pending'][$id]); saveConfig($configPath, $config);
    $cleaned = true;
    foreach ($files as $path) if (file_exists($path) && !@unlink($path)) $cleaned = false;
    reply(200, ['ok' => true, 'records' => records($config), 'message' => $cleaned ? '已删除这条记录。' : '条目已删除，部分证书文件未能清理，请检查程序目录的删除权限。']);
}
if (!$capable) fail(503, 'PHP 环境不能自动签发，请使用本地引导。');
$env = environment($body);
if (($body['termsAgreed'] ?? false) !== true) fail(400, '请先阅读并同意服务条款。');
if ($action === 'complete') {
    $id = $body['id'] ?? '';
    if (!is_string($id) || !isset($config['pending'][$id])) fail(404, '没有找到待验证的申请。');
    $pending = $config['pending'][$id]; $domainList = $pending['domains']; $env = $pending['environment'];
    $algorithm = $pending['keyAlgorithm']; $method = $pending['method']; $target = $pending['target']; $previous = $config['records'][$id] ?? null;
    if (($body['confirmed'] ?? false) !== true && count($pending['resources']) > 0) fail(400, '请先完成页面上的验证操作。');
} elseif ($action === 'renew') {
    $id = $body['id'] ?? '';
    if (!is_string($id) || !isset($config['records'][$id])) fail(404, '没有找到可续期的证书。');
    $previous = $config['records'][$id]; $domainList = $previous['domains']; $env = $previous['environment']; $algorithm = $previous['keyAlgorithm'];
    $method = $previous['method'] ?? 'http-01'; $target = $previous['target'] ?? 'site';
} else {
    if (!isset($body['domains']) || !is_array($body['domains'])) fail(400, '请填写域名。');
    $method = $body['method'] ?? 'http-01'; $target = $body['target'] ?? 'site';
    if (!in_array($method, ['http-01', 'dns-01'], true) || !in_array($target, ['site', 'other'], true)) fail(400, '申请方式无效。');
    $domainList = domains($body['domains'], $method); $algorithm = $body['keyAlgorithm'] ?? 'rsa-2048';
    if (!in_array($algorithm, ['rsa-2048', 'ec-p256'], true)) fail(400, '密钥类型无效。');
    $id = hash('sha256', $env . '|' . $algorithm . '|' . implode('|', $domainList)); $previous = $config['records'][$id] ?? null;
}
if ($env !== 'production') fail(400, '仅支持正式证书签发。');
// Repeated clicks before the renewal window return existing outputs, avoiding
// unnecessary orders. A new domain set always has a separate record.
if ($action !== 'complete' && $previous && time() < $previous['renewAt'] && time() < $previous['notAfter']) reply(200, resultData($previous, $root, true));
if ($action !== 'complete' && isset($config['pending'][$id]) && ($body['restart'] ?? false) !== true) reply(200, pendingData($config['pending'][$id]));
ignore_user_abort(true); @set_time_limit(240);
try {
    $ac = new AssistantACME($env);
    $currentTerms = $ac->getTermsURL();
    if (($body['termsUrl'] ?? '') !== $currentTerms) fail(409, '服务条款已更新，请重新检查连接并阅读条款。');
    $config['agreedTerms'][$env] = $currentTerms;
    if (!isset($config['accounts'][$env])) { $config['accounts'][$env] = $ac->generateRSAKey(2048); saveConfig($configPath, $config); }
    $ac->loadAccountKey($config['accounts'][$env]); $ac->register(true, []);
    if ($action === 'complete') {
        $privateKey = guardedRead($root . '/' . $pending['privateKeyFile']);
        $chain = $ac->finishManual($pending, $privateKey);
    } else {
    $privateKey = $algorithm === 'ec-p256' ? $ac->generateECKey('P-256') : $ac->generateRSAKey(2048);
    if ($target === 'other' || $method === 'dns-01') {
        $manual = $ac->beginManual($domainList, $method);
        $keyFile = 'ssl-private-key-' . substr($id, 0, 16) . '-' . bin2hex(random_bytes(6)) . '.php';
        guardedWrite($root . '/' . $keyFile, $privateKey . "\n");
        $pending = ['id' => $id, 'domains' => $domainList, 'environment' => $env, 'keyAlgorithm' => $algorithm,
            'method' => $method, 'target' => $target, 'privateKeyFile' => $keyFile] + $manual;
        $config['pending'][$id] = $pending; saveConfig($configPath, $config);
        if (count($pending['resources']) > 0) reply(200, pendingData($pending));
        $chain = $ac->finishManual($pending, $privateKey);
    } else {
    $settings = [];
    if ($previous) { try { $ari = $ac->getARI(guardedRead($root . '/' . $previous['certificateFile'])); $settings['replaces'] = $ari['ari_cert_id']; } catch (Throwable $error) { /* Official ARI optional; same-domain renewal remains supported. */ } }
    $domainConfig = array_fill_keys($domainList, ['challenge' => 'http-01']);
    $chain = $ac->getCertificateChain($privateKey, $domainConfig, static function ($options) use ($documentRoot) {
        if (!str_starts_with($options['key'], '/.well-known/acme-challenge/')) throw new RuntimeException('验证路径无效。');
        $created = placeFiles($documentRoot, [['name' => basename($options['key']), 'content' => $options['value']]]);
        return static function () use ($created) {
            foreach ($created as $path => $content) if (!is_link($path) && is_file($path) && @file_get_contents($path) === $content) @unlink($path);
        };
    }, $settings);
    }
    }
    $cert = openssl_x509_read($chain); $parsed = $cert ? openssl_x509_parse($cert) : false;
    if (!$cert || !$parsed || !openssl_x509_check_private_key($cert, $privateKey)) throw new RuntimeException('证书与私钥不匹配，已停止交付。');
    $sans = array_map('trim', explode(',', $parsed['extensions']['subjectAltName'] ?? ''));
    foreach ($domainList as $domain) if (!in_array('DNS:' . $domain, $sans, true)) throw new RuntimeException('证书没有覆盖所有域名，已停止交付。');
    $suffix = substr($id, 0, 16) . '-' . bin2hex(random_bytes(6));
    $certFile = 'ssl-certificate-' . $suffix . '.php'; $keyFile = 'ssl-private-key-' . $suffix . '.php';
    guardedWrite($root . '/' . $keyFile, $privateKey . "\n"); guardedWrite($root . '/' . $certFile, $chain);
    $before = (int) $parsed['validFrom_time_t']; $after = (int) $parsed['validTo_time_t'];
    $record = ['id' => $id, 'domains' => $domainList, 'environment' => $env, 'keyAlgorithm' => $algorithm, 'method' => $method, 'target' => $target,
        'notBefore' => $before, 'notAfter' => $after, 'renewAt' => (int) ($before + ($after - $before) * 2 / 3),
        'certificateFile' => $certFile, 'privateKeyFile' => $keyFile];
    try { $ari = $ac->getARI($chain); $record['renewAt'] = (int) (($ari['suggestedWindow']['start'] + $ari['suggestedWindow']['end']) / 2); } catch (Throwable $error) { /* Lifetime-based fallback. */ }
    $config['records'][$id] = $record; unset($config['pending'][$id]); saveConfig($configPath, $config);
    reply(200, resultData($record, $root));
} catch (AssistantInvalidOrder $error) {
    reply(422, ['ok' => false, 'invalidOrder' => true, 'message' => '本次验证未通过，请重新生成验证材料，并按页面指引上传文件或添加 DNS 记录。']);
} catch (\skoerfgen\ACMECert\ACME_Exception $error) {
    $type = $error->getType();
    $invalidOrder = $action === 'complete' && preg_match('/:(unauthorized|dns|connection|incorrectResponse)\z/', $type) === 1;
    reply(422, ['ok' => false, 'invalidOrder' => $invalidOrder, 'message' => '签发未完成：' . $error->getMessage() . '。请检查对应网站的文件或 DNS 验证；需要重试时按页面更新验证材料。']);
} catch (Throwable $error) {
    // Some upstream key errors include PEM in exception text: never expose them.
    fail(502, '证书还没有签发成功。请检查服务器网络和网站目录权限，再到“我的证书”查看进度。也可以在电脑上打开安装包里的 freessl.html，按提示申请。');
}

}
