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
	"errors"
	"fmt"
	"sync"

	"blockarchitech.com/timetodo/internal/models"
	"go.uber.org/zap"
)

// InMemoryUserRepository is an in-memory implementation of the UserRepository.
type InMemoryUserRepository struct {
	users  map[string]*models.User
	mu     sync.RWMutex
	logger *zap.Logger
}

// NewInMemoryUserRepository creates a new InMemoryUserRepository.
func NewInMemoryUserRepository(logger *zap.Logger) *InMemoryUserRepository {
	return &InMemoryUserRepository{
		users:  make(map[string]*models.User),
		logger: logger.Named("inmemory_user_repo"),
	}
}

func (r *InMemoryUserRepository) Create(ctx context.Context, user *models.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[user.PebbleAccountToken]; exists {
		return fmt.Errorf("user with pebble account token %s already exists", user.PebbleAccountToken)
	}
	r.users[user.PebbleAccountToken] = user
	r.logger.Info("Created user in-memory", zap.String("pebbleAccountToken", user.PebbleAccountToken))
	return nil
}

func (r *InMemoryUserRepository) GetByPebbleAccount(ctx context.Context, pebbleAccountToken string) (*models.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, exists := r.users[pebbleAccountToken]
	if !exists {
		return nil, nil // Not found
	}
	return user, nil
}

func (r *InMemoryUserRepository) GetByTodoistUserID(ctx context.Context, todoistUserID int64) (*models.User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, user := range r.users {
		if user.TodoistUserID == todoistUserID {
			return user, nil
		}
	}
	return nil, nil // Not found
}

func (r *InMemoryUserRepository) Update(ctx context.Context, user *models.User) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[user.PebbleAccountToken]; !exists {
		return fmt.Errorf("user with pebble account token %s not found", user.PebbleAccountToken)
	}
	r.users[user.PebbleAccountToken] = user
	r.logger.Info("Updated user in-memory", zap.String("pebbleAccountToken", user.PebbleAccountToken))
	return nil
}

func (r *InMemoryUserRepository) DeleteByPebbleAccount(ctx context.Context, pebbleAccountToken string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[pebbleAccountToken]; !exists {
		return fmt.Errorf("user with pebble account token %s not found", pebbleAccountToken)
	}
	delete(r.users, pebbleAccountToken)
	r.logger.Info("Deleted user in-memory", zap.String("pebbleAccountToken", pebbleAccountToken))
	return nil
}

func (r *InMemoryUserRepository) DeleteByTodoistUserID(ctx context.Context, todoistUserID int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var tokenToDelete string
	for token, user := range r.users {
		if user.TodoistUserID == todoistUserID {
			tokenToDelete = token
			break
		}
	}
	if tokenToDelete == "" {
		return errors.New("user not found")
	}
	delete(r.users, tokenToDelete)
	r.logger.Info("Deleted user by Todoist ID in-memory", zap.Int64("todoistUserID", todoistUserID))
	return nil
}

func (r *InMemoryUserRepository) UpdateUserPreferences(ctx context.Context, pebbleAccountToken string, prefs models.Preferences) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, exists := r.users[pebbleAccountToken]
	if !exists {
		return fmt.Errorf("user with pebble account token %s not found", pebbleAccountToken)
	}
	user.Preferences = prefs
	r.logger.Info("Updated user preferences in-memory", zap.String("pebbleAccountToken", pebbleAccountToken))
	return nil
}

func (r *InMemoryUserRepository) Close() error {
	r.logger.Info("Closing in-memory user repository (no-op).")
	return nil
}
