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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"blockarchitech.com/timetodo/internal/config"
)

type AuthUtils struct{}

// NewAuthUtils creates a new instance of AuthUtils.
func NewAuthUtils() *AuthUtils {
	return &AuthUtils{}
}

// SetCookie sets an HTTP cookie with common secure defaults.
func (a *AuthUtils) SetCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", // Check for TLS or proxy
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
}

// GenerateOAuthState creates a random base64 string for OAuth state.
func (a *AuthUtils) GenerateOAuthState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes for state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetTokensFromHeader retrieves Pebble account and timeline tokens from the Authorization header.
func (a *AuthUtils) GetTokensFromHeader(r *http.Request) (string, string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", "", fmt.Errorf("missing Authorization header")
	}
	parts := SplitAndTrim(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", "", fmt.Errorf("invalid Authorization header format")
	}
	// Base64 decode the token part
	if len(parts[1]) == 0 {
		return "", "", fmt.Errorf("missing token in Authorization header")
	}

	return a.getTokens(parts[1])
}

// GetTokensFromQuery retrieves Pebble account and timeline tokens from the query parameters.
func (a *AuthUtils) GetTokensFromQuery(r *http.Request) (string, string, error) {
	base := r.URL.Query().Get("token")
	if base == "" {
		return "", "", fmt.Errorf("missing token query parameter")
	}
	// Split the token into account and timeline tokens
	if !IsBase64(base) {
		return "", "", fmt.Errorf("invalid token format in query parameter, expected base64 encoded string")
	}

	return a.getTokens(base)
}

// GetTokensFromPebbleHeaders retrieves Pebble account and timeline tokens from a Timeline Action request.
func (a *AuthUtils) GetTokensFromPebbleHeaders(r *http.Request) (string, string, error) {
	accountToken := r.Header.Get("X-Pebble-Account-Token")
	timelineToken := r.Header.Get("X-Pebble-Timeline-Token")
	if accountToken == "" || timelineToken == "" {
		return "", "", fmt.Errorf("missing X-Pebble-Account-Token or X-Pebble-Timeline-Token header")
	}
	return accountToken, timelineToken, nil
}

// getTokens splits a base64 encoded token into account and timeline tokens.
func (a *AuthUtils) getTokens(b string) (string, string, error) {
	// Split the token into account and timeline tokens
	if !IsBase64(b) {
		return "", "", fmt.Errorf("invalid token format in Authorization header, expected base64 encoded string")
	}
	// Convert base64 to string
	decoded, err := base64.StdEncoding.DecodeString(b)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode base64 token: %w", err)
	}
	tokens := SplitAndTrim(string(decoded), ":")
	if len(tokens) != 2 {
		return "", "", fmt.Errorf("invalid token format in Authorization header")
	}
	return tokens[0], tokens[1], nil
}

// GetPebbleTokensFromCookies retrieves Pebble account and timeline tokens from request cookies.
func (a *AuthUtils) GetPebbleTokensFromCookies(r *http.Request) (string, string, error) {
	pebbleAccountTokenCookie, errAcc := r.Cookie(config.OauthPebbleAccountTokenCookieName)
	pebbleTimelineTokenCookie, errTime := r.Cookie(config.OauthPebbleTimelineTokenCookieName)

	if errAcc != nil {
		return "", "", fmt.Errorf("account token cookie error: %w", errAcc)
	}
	if errTime != nil {
		return "", "", fmt.Errorf("timeline token cookie error: %w", errTime)
	}

	return pebbleAccountTokenCookie.Value, pebbleTimelineTokenCookie.Value, nil
}

// ClearOAuthCookies removes OAuth-related cookies.
func (a *AuthUtils) ClearOAuthCookies(w http.ResponseWriter, r *http.Request) {
	a.SetCookie(w, r, config.OauthStateCookieName, "", -1)
	a.SetCookie(w, r, config.OauthPebbleAccountTokenCookieName, "", -1)
	a.SetCookie(w, r, config.OauthPebbleTimelineTokenCookieName, "", -1)
}
