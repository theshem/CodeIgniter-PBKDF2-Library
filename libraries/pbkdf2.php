<?php
defined('BASEPATH') or exit('No direct script access allowed');

/**
 * CodeIgniter PBKDF2 Library
 *
 * Copyright (c) 2012 Hashem Qolami. (http://qolami.com)
 * Released under the MIT license.
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * PBKDF2 (Password-Based Key Derivation Function 2) is a key derivation function
 * that is part of RSA Laboratories' Public-Key Cryptography Standards (PKCS) series,
 * specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's RFC 2898
 * (http://tools.ietf.org/html/rfc2898)
 *
 * 
 * @package  	CodeIgniter
 * @subpackage	Libraries
 * @category	Libraries
 * @author  	Hashem Qolami <hashem@qolami.com>
 * @link    	https://github.com/qolami/CodeIgniter-PBKDF2-Library
 * @license  	http://opensource.org/licenses/MIT (MIT license)
 * @copyright	2012 Hashem Qolami
 * @since   	1.0
 * @version  	1.0
 *
*/
class Pbkdf2 {

	/**
	 * Algorithm of hash operation
	 *
	 * @var string
	 */
	private $algorithm = 'sha256';

	/**
	 * Algorithm of hash operation
	 *
	 * @var int
	 */
	private $iterations = 1000;

	/**
	 * Length of hash
	 *
	 * @var int
	 */
	private $hash_length = 32;

	/**
	 * Length of salt
	 *
	 * @var int
	 */
	private $salt_length = 32;

	/**
	 * Get the properties of the class except $exception
	 *
	 * @param	mixed contains propert(y|ies) name to be ignored
	 * @return	array
	 */
	private function get_vars($exception=NULL) {
		$vars = get_class_vars(__CLASS__);
		
		if (isset($exception)) {
			if (is_array($exception)) {
				$vars = array_diff($vars, $exception);
			} else {
				unset($vars[$exception]);
			}
		}
		return $vars;
	}

	/**
	 * Initialize Pbkdf2 class by user configuration
	 *
	 * @param	array|null
	 * @return	void
	 */
	public function initialize($conf=NULL) {
		if (!isset($conf)) {
			return;
		}

		if (is_array($conf)) {
			if (isset($conf['algorithm']) && !in_array($conf['algorithm'], hash_algos(), TRUE)) {
			/*	
				try {
					throw new Exception("PBKDF2 ERROR: '$conf[algorithm]' hashing is not supported.\n");
				} catch (Exception $e) {
					echo $e->getMessage();
				}
			*/
				show_error("PBKDF2 ERROR: '$conf[algorithm]' hashing is not supported.");
				$conf['algorithm'] = $this->algorithm;
			}

			$vars = $this->get_vars();

			foreach ($conf as $key => $value) {
				if (array_key_exists($key, $vars)) {
					$this->$key = trim(strtolower($value));
				}
			}
		}
	}

	/**
	 * Encode $str to base64
	 *
	 * Removes first and last 2 characters from encoded $str,
	 * returns encoded string of predefined length.
	 *
	 * @param	string
	 * @return	string
	 */
	private function encode($str) {
		$length = strlen($str);
		$str = base64_encode($str);

		$diff = strlen($str) - $length;

		// remains at least 4 characters
		if ($diff >= 4) {
			$str = substr(substr($str, 0, -2), 2);
		}

		return substr($str, 0, $length);

		/* TODO: Research
			if($diff % 2 == 0) {
				$start = $end = $length/2;
			}else{
				$start = floor($length/2);
				$end = $start + 1;
			}
			return substr($str, -$end, $end).substr($str, 0, $start);
		*/
	}

	/**
	 * Generate salt
	 *
	 * Returns a string contains $bytes character
	 *
	 * @param	int
	 * @return	string
	 */
	private function gen_salt($bytes) {
		$init_vector = mcrypt_create_iv($bytes, MCRYPT_DEV_URANDOM);
		return $this->encode($init_vector);
	}

	/**
	 * PBKDF2 Encryption (Based on: http://www.ietf.org/rfc/rfc2898.txt)
	 *
	 * Returns a bin/hex string contains $key_length character
	 *
	 * @param	string	$algo	hash algorithm	(recommended sha256)
	 * @param	string	$P  	password
	 * @param	string	$S  	salt
	 * @param	int 	$C  	iteration count	(recommended >=1000)
	 * @param	int 	$dkLen	derived key length
	 * @return	string
	 */
	private function _pbkdf2($algo, $P, $S, $C, $dkLen) {
		
		// the length in octets of the pseudo-random function output
		$hLen = strlen(hash($algo, '', TRUE));

		// number of hLen-octet blocks in the derived key
		$l = ceil($dkLen / $hLen);

		// derived key
		$DK = '';

		// repeat the operation for each block of the derived key
		for ($i = 1; $i <= $l; $i++) {
			
			// concatenation of the salt $S and the block index $i
			// $i encoded as four-octet (32 bit) big endian
			// generate the first hash
			$Ui = $Tj = hash_hmac($algo, $S . pack('N', $i), $P, true);

			// perform the other ($C - 1) iterations
			for ($j = 1; $j < $C; $j++) {

				// the exclusive-or sum of the first $C iterates
				$Tj ^= ($Ui = hash_hmac($algo, $Ui, $P, true));
			}

			// Concatenate the blocks and extract the first dkLen octets to
			// produce a derived key DK
			$DK .= $Tj;
		}

		// Output the derived key DK of correct length
		return substr($DK, 0, $dkLen);
	}

	/**
	 * Encrypt
	 *
	 * Returns an array/object contains salt, password
	 * and hash string made by concatenating salt and password.
	 *
	 * There is some options for passing $good_hash through encrypt method.
	 * $good_hash can be a salt or a combination of salt and password
	 * called 'hash' in output array/object.
	 *
	 * @param	string	$password
	 * @param	mixed	$good_hash
	 * @param	bool	$object_output
	 * @return	array|object
	 */
	public function encrypt($password, $good_hash = NULL, $object_output = FALSE) {
		if (isset($good_hash) && is_bool($good_hash)) {
			$object_output = $good_hash;
			unset($good_hash);
		}

		if (!isset($good_hash)) {
			$salt = $this->gen_salt($this->salt_length);
		} else {
			if (strlen($good_hash) === (int)$this->salt_length) {
				$salt = $good_hash;
			} elseif (strlen($good_hash) === (int)$this->salt_length + (int)$this->hash_length) {
				$salt = substr($good_hash, 0, $this->salt_length);
			} else {
				show_error("PBKDF2 ERROR: Something's wrong with your hash!");
			}
		}

		$hash = $this->encode($this->_pbkdf2(
			$this->algorithm,
			$password,
			$salt,
			$this->iterations,
			$this->hash_length,
			TRUE
		));

		$return_arr = array(
			'salt'		=>	$salt,
			'password'	=>	$hash,
			'hash'		=>	$salt.$hash
		);

		if ($object_output) {
			return (object) $return_arr;
		} else {
			return $return_arr;
		}
	}

}

/* End of file pbkdf2.php */
/* Location: ./application/libraries/pbkdf2.php */