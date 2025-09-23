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

package repository

import (
	"context"

	"blockarchitech.com/timetodo/internal/models"
)

// UserRepository defines the interface for storing and retrieving user data.
type UserRepository interface {
	// CRUD operations
	Create(ctx context.Context, user *models.User) error
	GetByPebbleAccount(ctx context.Context, pebbleAccountToken string) (*models.User, error)
	GetByTodoistUserID(ctx context.Context, todoistUserID int64) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	DeleteByPebbleAccount(ctx context.Context, pebbleAccountToken string) error
	DeleteByTodoistUserID(ctx context.Context, todoistUserID int64) error
	UpdateUserPreferences(ctx context.Context, pebbleAccountToken string, prefs models.Preferences) error
	// Other methods
	Close() error
}
