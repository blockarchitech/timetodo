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

package storage

import (
	"context"
	"golang.org/x/oauth2"
	"time"
)

// UserTokens holds the various tokens for a user.
type UserTokens struct {
	PebbleAccountToken  string        `firestore:"pebbleAccountToken,omitempty"`
	PebbleTimelineToken string        `firestore:"pebbleTimelineToken,omitempty"`
	TodoistAccessToken  *oauth2.Token `firestore:"todoistAccessToken,omitempty"`
	TodoistUserID       int64         `firestore:"todoistUserID,omitempty"`
	LastUpdated         time.Time     `firestore:"lastUpdated,omitempty"`
}

// TokenStore defines the interface for storing and retrieving user tokens.
type TokenStore interface {
	StoreTokens(ctx context.Context, pebbleAccountToken string, tokens UserTokens) error
	GetTokensByPebbleAccount(ctx context.Context, pebbleAccountToken string) (UserTokens, bool, error)
	GetTokensByTodoistUserID(ctx context.Context, todoistUserID int64) (UserTokens, bool, error)
	Close() error
	DeleteTokensByTodoistUserID(ctx context.Context, id int64) error
}
