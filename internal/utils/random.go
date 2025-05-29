/*
 *    Copyright 2025 blockarchitech
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"io"
	"net/http"
	"strings"
)

// SplitAndTrim splits a string by a separator and trims whitespace from each part.
func SplitAndTrim(s string, sep string) []string {
	parts := strings.Split(s, sep)
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts
}

// IsBase64 checks if a string is a valid Base64 encoded string.
func IsBase64(s string) bool {
	// Check if the string is empty or too short to be Base64
	if len(s) == 0 || len(s)%4 != 0 {
		return false
	}

	// Check if the string contains only valid Base64 characters
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=') {
			return false
		}
	}

	return true
}

// HttpError logs an error, updates the span, and sends an HTTP error response.
func HttpError(w http.ResponseWriter, span trace.Span, l *zap.Logger, message string, err error, statusCode int) {
	l.Error(message, zap.Error(err))
	if span != nil {
		span.SetStatus(codes.Error, message)
		span.RecordError(err)
	}
	http.Error(w, message, statusCode)
}

// Encrypt encrypts a string using AES encryption.
func Encrypt(stringToEncrypt string, keyString string) (encryptedString string, err error) {
	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext), nil
}

// Decrypt decrypts an AES encrypted string.
func Decrypt(encryptedString string, keyString string) (decryptedString string, err error) {

	key, _ := hex.DecodeString(keyString)
	enc, _ := hex.DecodeString(encryptedString)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s", plaintext), nil
}

func IsEncrypted(s string, k string) bool {
	// Check if the string is AES encrypted by checking its length and if it contains only hex characters
	if len(s) < 32 || len(s)%2 != 0 {
		return false
	}

	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}

	_, err := Decrypt(s, k)
	if err != nil {
		return false
	}

	return true
}
