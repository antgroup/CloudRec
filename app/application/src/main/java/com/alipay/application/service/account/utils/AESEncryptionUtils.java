/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.alipay.application.service.account.utils;

import com.alipay.application.service.system.utils.SecretKeyUtil;
import lombok.extern.slf4j.Slf4j;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
public class AESEncryptionUtils {

    private static final String ALGORITHM = "AES";

    public static String encrypt(String data) {
        if (data == null || data.isEmpty()) {
            return null;
        }

        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    SecretKeyUtil.ACCESS_KEY_SECRET_KEY_ENCRYPT_VALUE.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

            byte[] encryptedBytes = cipher.doFinal(data.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SecretKey stringToSecretKey(String keyStr) {
        byte[] decodedKey = Base64.getDecoder().decode(keyStr);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    // Generate a random AES key
    public static String generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey key = keyGen.generateKey();
        return bytesToHex(key.getEncoded());
    }

    // Convert bytes to Hex
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String encrypt(String plaintext, String secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        byte[] iv = new byte[cipher.getBlockSize()];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, stringToSecretKey(secretKey), ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes());

        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);
        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    public static String decrypt(String encryptedData) {
        if (encryptedData == null || encryptedData.isEmpty()) {
            return null;
        }
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(
                    SecretKeyUtil.ACCESS_KEY_SECRET_KEY_ENCRYPT_VALUE.getBytes(), ALGORITHM);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

            byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            log.error("decrypt error", e);
        }
        return null;
    }

    public static String decrypt(String ciphertext, SecretKey key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(ciphertext);
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        int blockSize = cipher.getBlockSize();

        byte[] iv = new byte[blockSize];
        byte[] encrypted = new byte[decoded.length - blockSize];

        System.arraycopy(decoded, 0, iv, 0, blockSize);
        System.arraycopy(decoded, blockSize, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        byte[] original = cipher.doFinal(encrypted);

        return new String(original);
    }
}
