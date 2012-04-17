<?php

/*
Copyright (C) 2012 Jon Schang

This file is part of PasswordKeep, released under the LGPLv3

PasswordKeep is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

PasswordKeep is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with PasswordKeep.  If not, see <http://www.gnu.org/licenses/>.
*/

error_reporting(E_ALL);
ini_set("display_errors","true");

define("SALT","78@3#~~~!712asdf383*45");
define("KEY_STORE","/files/www/credentials.xml");

/**
 * NOTE: I actually got this at
 * http://www.itnewb.com/tutorial/PHP-Encryption-Decryption-Using-the-MCrypt-Library-libmcrypt
 * The original author is Andrew Johnson and, obviously, his code doesn't fall under my license
 * above.
 * 
 * @author Andrew Johnson
 */
class cryptastic {

	/** Encryption Procedure
	 *
	 *	@param   mixed    msg      message/data
	 *	@param   string   k        encryption key
	 *	@param   boolean  base64   base64 encode result
	 *
	 *	@return  string   iv+ciphertext+mac or
	 *           boolean  false on error
	*/
	public function encrypt( $msg, $k, $base64 = false ) {
		# open cipher module (do not change cipher/mode)
		if ( ! $td = mcrypt_module_open('rijndael-256', '', 'ctr', '') )
			return false;
		$msg = serialize($msg);							# serialize
		$iv  = mcrypt_create_iv(32, MCRYPT_RAND);		# create iv
		if ( mcrypt_generic_init($td, $k, $iv) !== 0 )	# initialize buffers
			return false;
		$msg  = mcrypt_generic($td, $msg);				# encrypt
		$msg  = $iv . $msg;								# prepend iv
		$mac  = $this->pbkdf2($msg, $k, 1000, 32);		# create mac
		$msg .= $mac;									# append mac
		mcrypt_generic_deinit($td);						# clear buffers
		mcrypt_module_close($td);						# close cipher module
		if ( $base64 ) $msg = base64_encode($msg);		# base64 encode?
		return $msg;									# return iv+ciphertext+mac
	}

	/** Decryption Procedure
	 *
	 *	@param   string   msg      output from encrypt()
	 *	@param   string   k        encryption key
	 *	@param   boolean  base64   base64 decode msg
	 *
	 *	@return  string   original message/data or
	 *           boolean  false on error
	*/
	public function decrypt( $msg, $k, $base64 = false ) {
		if ( $base64 ) $msg = base64_decode($msg);			# base64 decode?
		# open cipher module (do not change cipher/mode)
		if ( ! $td = mcrypt_module_open('rijndael-256', '', 'ctr', '') )
			return false;
		$iv  = substr($msg, 0, 32);							# extract iv
		$mo  = strlen($msg) - 32;							# mac offset
		$em  = substr($msg, $mo);							# extract mac
		$msg = substr($msg, 32, strlen($msg)-64);			# extract ciphertext
		$mac = $this->pbkdf2($iv . $msg, $k, 1000, 32);		# create mac
		if ( $em !== $mac )									# authenticate mac
			return false;
		if ( mcrypt_generic_init($td, $k, $iv) !== 0 )		# initialize buffers
			return false;
		$msg = mdecrypt_generic($td, $msg);					# decrypt
		$msg = unserialize($msg);							# unserialize
		mcrypt_generic_deinit($td);							# clear buffers
		mcrypt_module_close($td);							# close cipher module
		return $msg;										# return original msg
	}

	/** PBKDF2 Implementation (as described in RFC 2898);
	 *
	 *	@param   string  p   password
	 *	@param   string  s   salt
	 *	@param   int     c   iteration count (use 1000 or higher)
	 *	@param   int     kl  derived key length
	 *	@param   string  a   hash algorithm
	 *
	 *	@return  string  derived key
	*/
	public function pbkdf2( $p, $s, $c, $kl, $a = 'sha256' ) {
		$hl = strlen(hash($a, null, true));	# Hash length
		$kb = ceil($kl / $hl);				# Key blocks to compute
		$dk = '';							# Derived key
		# Create key
		for ( $block = 1; $block <= $kb; $block ++ ) {
			# Initial hash for this block
			$ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);
			# Perform block iterations
			for ( $i = 1; $i < $c; $i ++ ) 
				# XOR each iterate
				$ib ^= ($b = hash_hmac($a, $b, $p, true));
			$dk .= $ib; # Append iterated block
		}
		# Return derived key of correct length
		return substr($dk, 0, $kl);
	}
}

class PasswordManager {
	private $key = null;
	private $cryptasticKey = null;
	private $credentials = array();
	private $crypter = null;
	
	public function __construct($key) {
		$this->key = $key;
		$this->crypter = new cryptastic();
		$this->initKey();
	}
	
	public function encrypt($str) {
		return $this->crypter->encrypt($str,$this->cryptasticKey,true);
	}
	
	public function decrypt($str) {
		return $this->crypter->decrypt($str,$this->cryptasticKey,true);
	}
		
	public function open() {
		$key = $this->key;
		if( file_exists(KEY_STORE) ) {
			$rawXml = $this->decrypt(file_get_contents(KEY_STORE));
			if( strpos($rawXml,"credentials")===false ) {
				return false;
			} 
			$dom = new DOMDocument();
			$dom->loadXml($rawXml);
		} else {
			$dom = new DOMDocument();
			$dom->loadXml("<?xml version=\"1.0\"?><credentials/>");
		}
		$credentials = $dom->getElementsByTagName("credential");
		if( $credentials instanceof DOMNodeList && $credentials->length>0 ) {
			for( $i=0; $i<$credentials->length; $i++ ) {
				$cred = $credentials->item($i);
				$url = $cred->getAttribute("url");
				$name = $cred->getAttribute("username");
				$pass = $cred->getAttribute("password");
				$desc = $cred->getAttribute("description");
				$this->credentials[] = new Credential($url,$name,$pass,$desc);
			}
		}
		return true;
	}
	
	public function store() {
		$dom = new DOMDocument();
		$creds = $dom->createElement("credentials");
		$dom->appendChild($creds);
		foreach( $this->credentials as $c ) {
			$cred = $dom->createElement("credential");
			$cred->setAttribute("url",$c->getUrl());
			$cred->setAttribute("username",$c->getUsername());
			$cred->setAttribute("password", $c->getPassword() );
			$cred->setAttribute("description",$c->getDescription());
			$creds->appendChild($cred);
		}
		$enc = $dom->saveXML();
		file_put_contents(KEY_STORE,$this->encrypt($enc));
	}
	
	private function initKey() {
		$this->cryptasticKey = $this->crypter->pbkdf2($this->key,SALT,2353,32);
	}
	
	public function setKey($key) {
		$this->key = $key;
	}
	private function getKeyValue() {
		return pack('H*',sha1($this->key.SALT));
	}
	
	public function getCredentials() {
		return $this->credentials;
	}
	public function setCredentials($credentials) {
		$this->credentials = $credentials;
	}
}

class Credential {
	private $username = "";
	private $description = "";
	private $url = "";
	private $password = "";

	public function __construct($url,$username,$password,$description) {
		$this->username = $username;
		$this->password = $password;
		$this->description = $description;
		$this->url = $url;
	}
	
	public function getUsername() { return $this->username; }
	public function getDescription() { return $this->description; }
	public function getPassword() { return $this->password; }
	public function getUrl() { return $this->url; }
	
	public function isComplete() {
		return !( empty($this->username) || empty($this->password) || empty($this->url) );
	}
	
	static public function compareTo($one,$two) {
		$ar = array($one->getUrl(),$two->getUrl());
		sort($ar);
		if( $one->getUrl() == $two->getUrl() )
			return 0;
		return $one->getUrl() == $ar[0] ? -1 : 1;
	}
}

$ret = true;
if( isset($_POST['key']) ) {
	$pm = new PasswordManager(trim($_REQUEST['key']));
	$ret = $pm->open();
} 

if( empty($_REQUEST['key']) || $ret!==true ) {
	if( $ret!==true ) {
		?><ul><li>Unable to decrypt store using supplied key.</li></ul><?
	}
	?><form method="post"><input type="password" name="key"/><input type="submit"/></form><?
} else {
	
	$credentials = $pm->getCredentials();
	if( !empty($_POST['url']) ) {
		$newCreds = array();
		$cnt = count($_POST['url']);
		for( $i=0; $i<$cnt; $i++ ) {
			foreach( array('username','password','url','description') as $col ) {
				if( empty($_POST[$col][$i] ) ) {
					$_POST[$col][$i]="";
				}
			}
			
			$cred = new Credential(
				$_POST['url'][$i],
				$_POST['username'][$i],
				$_POST['password'][$i],
				$_POST['description'][$i]);
				
			if( empty($_POST['delete'][$i]) && $cred->isComplete() ) {
				$newCreds[]=$cred;
			}
		}
		
		if( !empty($newCreds) ) {
			if( !empty($_REQUEST['new_key']) ) {
				if( $_REQUEST['new_key']==$_REQUEST['new_key_verify'] ) { 
					$_REQUEST['key']=$_REQUEST['new_key'];
					$pm = new PasswordManager($_REQUEST['key']);
				} else {
					echo '<ul><li>New key and key verify did not match.</li></ul>';
				}
			}		
			$pm->setCredentials($newCreds);
			$pm->store();
			$credentials = $newCreds;
		}
	}
	
	usort($credentials,array('Credential','compareTo'));
	
	?><form autocomplete="off" id="credentials_form" method="post">
		<input type="submit"/>
		<input type="hidden" name="key" value="<?=trim($_REQUEST['key'])?>"/>
    	<input type="password" name="new_key" value="<?=trim($_REQUEST['key'])?>"/>
		<input type="password" name="new_key_verify" value="<?=trim($_REQUEST['key'])?>"/>
    	<table>
			<tr>
                <td>X</td>
                <td>Url</td>
		<td>Link</td>
                <td>User</td>
                <td>Pass</td>
                <td>Desc</td>
            </tr>
            <tr>
                <td>&nbsp;</td>
                <td><input name="url[0]" value=""/></td>
		<td>&nbsp;</td>
                <td><input name="username[0]" value=""/></td>
                <td><input name="password[0]" value="" type="password"/></td>
                <td><input name="description[0]" value=""/></td>
            </tr>
	<?
	$i=1;
	foreach($credentials as $c) {
		?>
        <tr>
        	<td><input name="delete[<?=$i?>]" type="checkbox"/></td>
        	<td><input name="url[<?=$i?>]" value="<?=$c->getUrl()?>"/></td>
		<td><a target="_blank" href="<?=$c->getUrl()?>">link</a></td>
            <td><input name="username[<?=$i?>]" value="<?=$c->getUsername()?>"/></td>
            <td><input style="text-color:#fff;background-color:#fff;color:#fff;" name="password[<?=$i?>]" value="<?=$c->getPassword()?>"/></td>
            <td><input name="description[<?=$i?>]" value="<?=$c->getDescription()?>"/></td>
        </tr>
		<?
		$i++;
	}
	?>
	</table></form>
	<?
}
