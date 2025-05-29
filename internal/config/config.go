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

package config

import (
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

const (
	OauthStateCookieName               = "timetodo_oauth_state"
	OauthPebbleAccountTokenCookieName  = "timetodo_oauth_p_acc_token"
	OauthPebbleTimelineTokenCookieName = "timetodo_oauth_p_timeline_token"
	OauthCookieMaxAge                  = 300 // 5 minutes
	PebbleCloseSuccessURL              = "pebblejs://close#{\"status\":\"success\"}"
	PebbleCloseLogoutURL               = "pebblejs://close#{\"status\":\"logout\"}"
)

// Config holds the application configuration values.
type Config struct {
	Port                 string
	TodoistClientID      string
	TodoistClientSecret  string
	AppBaseURL           string
	SecretKey            string
	StorageType          string
	GCPProjectID         string
	PebbleTimelineAPIURL string
	OtelExporterEndpoint string
	TodoistOAuthConfig   *oauth2.Config
	Version              string
}

// LoadConfig loads configuration from environment variables.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Port:                 getEnv("PORT", "8080"),
		TodoistClientID:      getEnv("TODOIST_CLIENT_ID", ""),
		TodoistClientSecret:  getEnv("TODOIST_CLIENT_SECRET", ""),
		AppBaseURL:           getEnv("APP_BASE_URL", "http://localhost:8080"),
		SecretKey:            getEnv("SECRET_KEY", ""),
		StorageType:          getEnv("STORAGE_TYPE", "inmemory"),
		GCPProjectID:         getEnv("GCP_PROJECT_ID", ""),
		PebbleTimelineAPIURL: getEnv("PEBBLE_TIMELINE_API_URL", "https://timeline-sync.rebble.io"),
		OtelExporterEndpoint: getEnv("OTEL_EXPORTER_ENDPOINT", ""),
		Version:              getEnv("VERSION", "dev"),
	}

	if cfg.TodoistClientID == "" || cfg.TodoistClientSecret == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("TODOIST_CLIENT_ID, TODOIST_CLIENT_SECRET, or SECRET_KEY is not set")
	}

	if cfg.StorageType == "firestore" && cfg.GCPProjectID == "" {
		return nil, fmt.Errorf("STORAGE_TYPE is 'firestore' but GCP_PROJECT_ID is not set")
	}

	cfg.TodoistOAuthConfig = &oauth2.Config{
		ClientID:     cfg.TodoistClientID,
		ClientSecret: cfg.TodoistClientSecret,
		RedirectURL:  cfg.AppBaseURL + "/auth/todoist/callback",
		Scopes:       []string{"data:read"},

		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://todoist.com/oauth/authorize",
			TokenURL: "https://todoist.com/oauth/access_token",
		},
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
