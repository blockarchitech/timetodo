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
	"errors"
	"fmt"
	"time"

	"cloud.google.com/go/firestore"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.uber.org/zap"
)

const defaultTokenCollectionName = "userTokens"

type FirestoreTokenStore struct {
	client         *firestore.Client
	logger         *zap.Logger
	collectionName string
}

func NewFirestoreTokenStore(ctx context.Context, projectID string, logger *zap.Logger) (*FirestoreTokenStore, error) {
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		logger.Error("Failed to create Firestore client", zap.String("projectID", projectID), zap.Error(err))
		return nil, fmt.Errorf("firestore.NewClient: %w", err)
	}
	logger.Info("Successfully connected to Firestore", zap.String("projectID", projectID))
	return &FirestoreTokenStore{
		client:         client,
		logger:         logger.Named("firestore_store"),
		collectionName: defaultTokenCollectionName,
	}, nil
}

func (s *FirestoreTokenStore) StoreTokens(ctx context.Context, pebbleAccountToken string, tokens UserTokens) error {
	tokens.LastUpdated = time.Now()
	_, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Set(ctx, tokens)
	if err != nil {
		s.logger.Error("Failed to store tokens in Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return fmt.Errorf("failed to set document: %w", err)
	}
	s.logger.Info("Successfully stored tokens", zap.String("pebbleAccountToken", pebbleAccountToken))
	return nil
}

func (s *FirestoreTokenStore) GetTokensByPebbleAccount(ctx context.Context, pebbleAccountToken string) (UserTokens, bool, error) {
	dsnap, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.logger.Info("Tokens not found for pebbleAccountToken", zap.String("pebbleAccountToken", pebbleAccountToken))
			return UserTokens{}, false, nil
		}
		s.logger.Error("Failed to get tokens from Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return UserTokens{}, false, fmt.Errorf("failed to get document: %w", err)
	}

	var tokens UserTokens
	if err := dsnap.DataTo(&tokens); err != nil {
		s.logger.Error("Failed to decode token data from Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return UserTokens{}, false, fmt.Errorf("failed to decode token data: %w", err)
	}
	s.logger.Debug("Successfully retrieved tokens", zap.String("pebbleAccountToken", pebbleAccountToken))
	return tokens, true, nil
}

func (s *FirestoreTokenStore) GetTokensByTodoistUserID(ctx context.Context, todoistUserID int64) (UserTokens, bool, error) {
	iter := s.client.Collection(s.collectionName).Where("todoistUserID", "==", todoistUserID).Limit(1).Documents(ctx)
	defer iter.Stop()

	dsnap, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			s.logger.Info("Tokens not found for todoistUserID", zap.Int64("todoistUserID", todoistUserID))
			return UserTokens{}, false, nil
		}
		s.logger.Error("Failed to query tokens by TodoistUserID from Firestore", zap.Int64("todoistUserID", todoistUserID), zap.Error(err))
		return UserTokens{}, false, fmt.Errorf("failed to query tokens by TodoistUserID: %w", err)
	}

	var tokens UserTokens
	if err := dsnap.DataTo(&tokens); err != nil {
		s.logger.Error("Failed to decode token data from Firestore (by TodoistUserID)", zap.Int64("todoistUserID", todoistUserID), zap.Error(err))
		return UserTokens{}, false, fmt.Errorf("failed to decode token data: %w", err)
	}
	s.logger.Debug("Successfully retrieved tokens by TodoistUserID", zap.Int64("todoistUserID", todoistUserID))
	return tokens, true, nil
}

func (s *FirestoreTokenStore) DeleteTokensByTodoistUserID(ctx context.Context, id int64) error {
	iter := s.client.Collection(s.collectionName).Where("todoistUserID", "==", id).Limit(1).Documents(ctx)
	defer iter.Stop()

	dsnap, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			s.logger.Info("No tokens found to delete for TodoistUserID", zap.Int64("todoistUserID", id))
			return nil
		}
		s.logger.Error("Failed to query tokens by TodoistUserID for deletion", zap.Int64("todoistUserID", id), zap.Error(err))
		return fmt.Errorf("failed to query tokens by TodoistUserID: %w", err)
	}

	_, err = dsnap.Ref.Delete(ctx)
	if err != nil {
		s.logger.Error("Failed to delete tokens from Firestore", zap.Int64("todoistUserID", id), zap.Error(err))
		return fmt.Errorf("failed to delete document: %w", err)
	}

	s.logger.Info("Successfully deleted tokens for TodoistUserID", zap.Int64("todoistUserID", id))
	return nil
}

func (s *FirestoreTokenStore) Close() error {
	return s.client.Close()
}
