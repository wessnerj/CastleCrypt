<?php
/*******************************************************************************
 * This file is part of CastleCrypt
 *******************************************************************************
 *
 * (C) Copyright 2012, Joseph Wessner <castleCrypt@hdr.meetr.de>
 *
 * CastleCrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; If not,
 * see <http://www.gnu.org/licenses/>.
 *
 *******************************************************************************
 */

/**
 * @author Joseph Wessner <castleCrypt@hdr.meetr.de>
 */
class CastleCrypt {
	/**
	 * @var resource key resource identifier for private key
	 */
	private $__privateKey = false;
	/**
	 * @var resource key resource identifier for public key
	 */
	private $__publicKey = false;

	/**
	 * @var int keySize in Byte (256 Byte = 2048 Bit), CastleCrypt supports only 2048 Bit keySize atm
	 */
	private $__keySize = 256;
	/**
	 * @var int keySize in Byte for AES keys (24 Byte = 192 Bit), CastleCrypt supports only 192 Bit AES keys atm
	 */
	private $__keySizeAES = 24;

	/**
	 * @var string has to be the same value for all participants
	 */
	private $__defaultIV = 'ThoheeWehtai3EPhoUea4Aix';

	/**
	 * If this bit is set, hybrid encrption is used.
	 * @var int BitMask for checking the first bit of a byte (1 << 7)
	 */
	private static $__methodMask = 0x80;
	/**
	 * @var int BitMask for checking the second bit of a byte (1 << 6)
	 */
	// private static $__signMask = 0x40;

	/**
	 * @var int the key length field of the output is left-shifted by this constant (or right-shifted for input)
	 */
	private static $__keyLengthMultiplier = 5;
	/**
	 * @var int constant for better code reading; don't change
	 */
	private static $__keyLengthFieldSize = 1;

	/**
	 * Set privateKey (used for decryption)
	 *
	 * If you want to use a private key from PEM-file you have to call file_get_contents first, e.g.
	 * $castleCrypt->setPrivateKey(file_get_contents('path/to/private_key.pem'));
	 *
	 * @param $key private key in PEM format
	 * @return bool true on success
	 */
	public function setPrivateKey($key) {
		$this->__privateKey = openssl_pkey_get_private($key);
		return ($this->__privateKey !== false);
	}

	/**
	 * Set publicKey (used for encryption)
	 *
	 * If you want to use a public key from PEM-file you have to call file_get_contents first, e.g.
	 * $casteCrypt->setPublicKey(file_get_contents('path/to/public_key.pem'));
	 *
	 * @param $key public key in PEM format
	 * @return bool true on success
	 */
	public function setPublicKey($key) {
		$this->__publicKey = openssl_pkey_get_public($key);
		return ($this->__publicKey !== false);
	}

	/**
	 * Encrypt $data with public key
	 *
	 * @param $data data to encrypt
	 * @return string encrypted data
	 */
	public function encrypt($data) {
		$encryptedData = '';
		$prefix = 0;

		if (strlen($data) < $this->__keySize - 11) {
			// We can use RSA without AES
			$encryptedData = $this->__doRSAEncryption($data);
		} else {
			// $data is too big, use hybrid method with AES
			// Set hybrid mode bit
			$prefix |= self::$__methodMask;

			// generate AES key
			$aesKey = $this->__getRandomKey();

			// encrypt AES key with RSA
			$encryptedKey = $this->__doRSAEncryption($aesKey);

			// encrypt data with AES
			$aesCrypted = $this->__doAESEncryption($aesKey, $data);

			// calculate key length
			$keyLength = strlen($encryptedKey) >> self::$__keyLengthMultiplier;

			$encryptedData = chr($keyLength) . $encryptedKey . $aesCrypted;
		}

		return chr($prefix) . $encryptedData;
	}

	/**
	 * Decrypt $data with private key
	 *
	 * @param $data data to decrypt
	 * @return bool|string decrypted data
	 */
	public function decrypt($data) {
		$decryptedData = '';
		$prefix = ord(substr($data, 0, 1));
		$cryptedData = substr($data, 1);

		if ($prefix & self::$__methodMask) {
			// hybrid mode was used for encryption
			// get AES key length
			$keyLengthInBytes = ord(substr($cryptedData, 0, self::$__keyLengthFieldSize)) << self::$__keyLengthMultiplier;

			// get AES key
			$encryptedKey = substr($cryptedData, self::$__keyLengthFieldSize, $keyLengthInBytes);
			$key = $this->__doRSADecryption($encryptedKey);

			// decrypt data
			$aesData = substr($cryptedData, self::$__keyLengthFieldSize + $keyLengthInBytes);
			$decryptedData = $this->__doAESDecryption($key, $aesData);
		} else {
			// only RSA encryption was used
			$decryptedData = $this->__doRSADecryption($cryptedData);
		}

		return $decryptedData;
	}

	/**
	 * Encrypt $data with $this->__publicKey (Uses RSA only)
	 *
	 * @param $data data to encrypt
	 * @return string encrypted data
	 * @throws Exception if encryption went wrong
	 */
	private function __doRSAEncryption($data) {
		$crypted = false;
		if (openssl_public_encrypt($data, $crypted, $this->__publicKey, OPENSSL_PKCS1_PADDING))
			return $crypted;

		throw new Exception('Public encrypt error');
		return false;
	}

	/**
	 * Decrypt $data with $this->__privateKey (Uses RSA only)
	 *
	 * @param $data data to decrypt
	 * @return bool|string decrypted data
	 * @throws Exception if decryption went wrong
	 */
	private function __doRSADecryption($data) {
		$decrypted = false;
		if (openssl_private_decrypt($data, $decrypted, $this->__privateKey, OPENSSL_PKCS1_PADDING))
			return $decrypted;

		throw new Exception('Private decrypt error');
		return false;
	}

	/**
	 * Get a random string (byteArray) of $size.
	 *
	 * @param null $size size of key in bytes (null: use default AES keyLength)
	 * @return string key of $size Bytes
	 */
	private function __getRandomKey($size = null) {
		if (is_null($size))
			$size = $this->__keySizeAES;

		$key = '';

		// Use /dev/urandom if possible
		if (@is_readable('/dev/urandom')) {
			$f=fopen('/dev/urandom', 'rb');
			$key = fread($f, $size);
			fclose($f);
		}

		while (strlen($key) < $size) {
			$key .= chr(mt_rand(0, 0xFF));
		}

		return $key;
	}

	/**
	 * Encrypt $data with $key. (Uses AES only)
	 *
	 * This method uses AES-192 with CBC
	 *
	 * @param $key
	 * @param $data
	 * @return string
	 */
	private function __doAESEncryption($key, $data) {
		// add padding
		$data = $this->__pkcs5Pad($data, mcrypt_get_block_size(MCRYPT_RIJNDAEL_192, MCRYPT_MODE_CBC));

		// load cipher
		$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_192, '', MCRYPT_MODE_CBC, '');
		mcrypt_generic_init($cipher, $key, $this->__defaultIV);

		// encrypt
		$data = mcrypt_generic($cipher, $data);

		// clean up
		mcrypt_generic_deinit($cipher);

		return $data;
	}

	/**
	 * Decrypt $data with $key. (Uses AES only)
	 *
	 * This method uses AES-192 with CBC
	 *
	 * @param $key
	 * @param $data
	 * @return string
	 */
	private function __doAESDecryption($key, $data) {
		// load cipher
		$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_192, '', MCRYPT_MODE_CBC, '');
		mcrypt_generic_init($cipher, $key, $this->__defaultIV);

		// decrypt
		$data = mdecrypt_generic($cipher, $data);

		// clean up
		mcrypt_generic_deinit($cipher);

		return $this->__pkcs5Unpad($data);
	}

	/**
	 * Adds pkcs5 padding
	 * @return Given text with pkcs5 padding
	 * @param string $data String to pad
	 * @param integer $blocksize Blocksize used by encryption
	 */
	private function __pkcs5Pad($data, $blocksize){
		$pad = $blocksize - (strlen($data) % $blocksize);
		$returnValue = $data . str_repeat(chr($pad), $pad);

		return $returnValue;
	}

	/**
	 * Removes padding
	 * @return Given text with removed padding characters
	 * @param string $data String to unpad
	 */
	private function __pkcs5Unpad($data) {
		$pad = ord($data{strlen($data)-1});
		if ($pad > strlen($data)) return false;
		if (strspn($data, chr($pad), strlen($data) - $pad) != $pad) return false;

		return substr($data, 0, -1 * $pad);
	}
}
