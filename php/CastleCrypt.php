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
	 * If this bit is set, hybrid encrption is used.
	 * @var int BitMask for checking the first bit of a byte (1 << 7)
	 */
	private static $__methodMask = 0x80;
	/**
	 * @var int BitMask for checking the second bit of a byte (1 << 6)
	 */
	// private static $__signMask = 0x40;

	/**
	 * Set privateKey (used for decryption)
	 *
	 * If you want to use a private key from PEM-file you have to call file_get_contents first, e.g.
	 * $casteCrypt->setPrivateKey(file_get_contents('path/to/private_key.pem'));
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
		$prefix = chr(0);

		if (strlen($data) < $this->__keySize - 11) {
			// We can use RSA without AES
			$encryptedData = $this->__doRSAEncryption($data);
		} else {
			// $data is too big, use hybrid method with AES
			// TODO
		}

		return $prefix . $encryptedData;
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
			// TODO
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
}
