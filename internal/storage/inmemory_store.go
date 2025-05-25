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
	"sync"
	"time"

	"go.uber.org/zap"
)

type InMemoryTokenStore struct {
	mu                sync.RWMutex
	tokensByPebbleAcc map[string]User
	tokensByTodoistID map[int64]User
	logger            *zap.Logger
}

func NewInMemoryTokenStore(logger *zap.Logger) *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokensByPebbleAcc: make(map[string]User),
		tokensByTodoistID: make(map[int64]User),
		logger:            logger.Named("inmemory_store"),
	}
}

func (s *InMemoryTokenStore) StoreTokens(ctx context.Context, pebbleAccountToken string, tokens User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tokens.LastUpdated = time.Now()
	s.tokensByPebbleAcc[pebbleAccountToken] = tokens
	if tokens.TodoistUserID != 0 {
		s.tokensByTodoistID[tokens.TodoistUserID] = tokens
	}
	s.logger.Info("Successfully stored tokens", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Int64("todoistUserID", tokens.TodoistUserID))
	return nil
}

func (s *InMemoryTokenStore) GetTokensByPebbleAccount(ctx context.Context, pebbleAccountToken string) (User, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens, found := s.tokensByPebbleAcc[pebbleAccountToken]
	if !found {
		s.logger.Info("Tokens not found for pebbleAccountToken", zap.String("pebbleAccountToken", pebbleAccountToken))
	}
	s.logger.Debug("Successfully retrieved tokens", zap.String("pebbleAccountToken", pebbleAccountToken))
	return tokens, found, nil
}

func (s *InMemoryTokenStore) GetTokensByTodoistUserID(ctx context.Context, todoistUserID int64) (User, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	tokens, found := s.tokensByTodoistID[todoistUserID]
	if !found {
		s.logger.Info("Tokens not found for todoistUserID", zap.Int64("todoistUserID", todoistUserID))
	}
	s.logger.Debug("Successfully retrieved tokens by todoistUserID", zap.Int64("todoistUserID", todoistUserID))
	return tokens, found, nil
}

func (s *InMemoryTokenStore) DeleteTokensByTodoistUserID(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.tokensByTodoistID[id]; !found {
		s.logger.Info("No tokens found to delete for todoistUserID", zap.Int64("todoistUserID", id))
		return nil
	}
	delete(s.tokensByTodoistID, id)
	s.logger.Info("Successfully deleted tokens by todoistUserID", zap.Int64("todoistUserID", id))
	return nil
}

func (s *InMemoryTokenStore) Close() error {
	s.logger.Info("Closing InMemoryTokenStore (no-op)")
	return nil
}
