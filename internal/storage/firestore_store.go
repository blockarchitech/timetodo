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
	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/utils"
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

const defaultTokenCollectionName = "users"

type FirestoreTokenStore struct {
	client         *firestore.Client
	logger         *zap.Logger
	collectionName string
	config         *config.Config
}

func NewFirestoreTokenStore(ctx context.Context, projectID string, logger *zap.Logger, config *config.Config) (*FirestoreTokenStore, error) {
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
		config:         config,
	}, nil
}

func (s *FirestoreTokenStore) StoreTokens(ctx context.Context, pebbleAccountToken string, tokens User) error {
	tokens.LastUpdated = time.Now()

	if s.config.SecretKey != "" {
		encryptedTimelineToken, err := utils.Encrypt(tokens.PebbleTimelineToken, s.config.SecretKey)
		if err != nil {
			s.logger.Error("Failed to encrypt Pebble Timeline token", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
			return fmt.Errorf("failed to encrypt Pebble Timeline token: %w", err)
		}
		tokens.PebbleTimelineToken = encryptedTimelineToken

		encryptedTodoistAccessToken, err := utils.Encrypt(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey)
		if err != nil {
			s.logger.Error("Failed to encrypt Todoist access token", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
			return fmt.Errorf("failed to encrypt Todoist access token: %w", err)
		}
		tokens.TodoistAccessToken.AccessToken = encryptedTodoistAccessToken
	}

	_, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Set(ctx, tokens)
	if err != nil {
		s.logger.Error("Failed to store tokens in Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return fmt.Errorf("failed to set document: %w", err)
	}
	s.logger.Info("Successfully stored tokens", zap.String("pebbleAccountToken", pebbleAccountToken))
	return nil
}

func (s *FirestoreTokenStore) GetTokensByPebbleAccount(ctx context.Context, pebbleAccountToken string) (User, bool, error) {
	dsnap, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.logger.Info("Tokens not found for pebbleAccountToken", zap.String("pebbleAccountToken", pebbleAccountToken))
			return User{}, false, nil
		}
		s.logger.Error("Failed to get tokens from Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return User{}, false, fmt.Errorf("failed to get document: %w", err)
	}

	var tokens User
	if err := dsnap.DataTo(&tokens); err != nil {
		s.logger.Error("Failed to decode token data from Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return User{}, false, fmt.Errorf("failed to decode token data: %w", err)
	}
	s.logger.Debug("Successfully retrieved tokens", zap.String("pebbleAccountToken", pebbleAccountToken))

	// Migration - if tokens are _not_ encrypted, we assume they are legacy tokens and encrypt them and then store them in the db before returning.
	if tokens.PebbleTimelineToken != "" && !utils.IsEncrypted(tokens.PebbleTimelineToken, s.config.SecretKey) {
		s.logger.Info("Migrating legacy Pebble Timeline token", zap.String("pebbleAccountToken", pebbleAccountToken))
		tokens.PebbleTimelineToken, err = utils.Encrypt(tokens.PebbleTimelineToken, s.config.SecretKey)
		if err != nil {
			s.logger.Error("Failed to encrypt legacy Pebble Timeline token", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to encrypt Pebble Timeline token: %w", err)
		}
		_, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Set(ctx, tokens)
		if err != nil {
			s.logger.Error("Failed to update legacy Pebble Timeline token in Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to update document with encrypted token: %w", err)
		}
	}
	if tokens.TodoistAccessToken.AccessToken != "" && !utils.IsEncrypted(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey) {
		s.logger.Info("Migrating legacy Todoist access token", zap.String("pebbleAccountToken", pebbleAccountToken))
		tokens.TodoistAccessToken.AccessToken, err = utils.Encrypt(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey)
		if err != nil {
			s.logger.Error("Failed to encrypt legacy Todoist access token", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to encrypt Todoist access token: %w", err)
		}
		_, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Set(ctx, tokens)
		if err != nil {
			s.logger.Error("Failed to update legacy Todoist access token in Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to update document with encrypted token: %w", err)
		}
	}

	tokens, err = s.decryptTokens(&tokens)
	if err != nil {
		s.logger.Error("Failed to decrypt tokens", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return User{}, false, fmt.Errorf("failed to decrypt tokens: %w", err)
	}
	return tokens, true, nil
}

func (s *FirestoreTokenStore) GetTokensByTodoistUserID(ctx context.Context, todoistUserID int64) (User, bool, error) {
	iter := s.client.Collection(s.collectionName).Where("todoistUserID", "==", todoistUserID).Limit(1).Documents(ctx)
	defer iter.Stop()

	dsnap, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			s.logger.Info("Tokens not found for todoistUserID", zap.Int64("todoistUserID", todoistUserID))
			return User{}, false, nil
		}
		s.logger.Error("Failed to query tokens by TodoistUserID from Firestore", zap.Int64("todoistUserID", todoistUserID), zap.Error(err))
		return User{}, false, fmt.Errorf("failed to query tokens by TodoistUserID: %w", err)
	}

	var tokens User
	if err := dsnap.DataTo(&tokens); err != nil {
		s.logger.Error("Failed to decode token data from Firestore (by TodoistUserID)", zap.Int64("todoistUserID", todoistUserID), zap.Error(err))
		return User{}, false, fmt.Errorf("failed to decode token data: %w", err)
	}
	s.logger.Debug("Successfully retrieved tokens by TodoistUserID", zap.Int64("todoistUserID", todoistUserID))

	// Migration - if tokens are _not_ encrypted, we assume they are legacy tokens and encrypt them and then store them in the db before returning.
	if tokens.PebbleTimelineToken != "" && !utils.IsEncrypted(tokens.PebbleTimelineToken, s.config.SecretKey) {
		s.logger.Info("Migrating legacy Pebble Timeline token", zap.String("pebbleAccountToken", tokens.PebbleAccountToken))
		tokens.PebbleTimelineToken, err = utils.Encrypt(tokens.PebbleTimelineToken, s.config.SecretKey)
		if err != nil {
			s.logger.Error("Failed to encrypt legacy Pebble Timeline token", zap.String("pebbleAccountToken", tokens.PebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to encrypt Pebble Timeline token: %w", err)
		}
		_, err := s.client.Collection(s.collectionName).Doc(tokens.PebbleAccountToken).Set(ctx, tokens)
		if err != nil {
			s.logger.Error("Failed to update legacy Pebble Timeline token in Firestore", zap.String("pebbleAccountToken", tokens.PebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to update document with encrypted token: %w", err)
		}
	}
	if tokens.TodoistAccessToken.AccessToken != "" && !utils.IsEncrypted(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey) {
		s.logger.Info("Migrating legacy Todoist access token", zap.String("pebbleAccountToken", tokens.PebbleAccountToken))
		tokens.TodoistAccessToken.AccessToken, err = utils.Encrypt(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey)
		if err != nil {
			s.logger.Error("Failed to encrypt legacy Todoist access token", zap.String("pebbleAccountToken", tokens.PebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to encrypt Todoist access token: %w", err)
		}
		_, err := s.client.Collection(s.collectionName).Doc(tokens.PebbleAccountToken).Set(ctx, tokens)
		if err != nil {
			s.logger.Error("Failed to update legacy Todoist access token in Firestore", zap.String("pebbleAccountToken", tokens.PebbleAccountToken), zap.Error(err))
			return User{}, false, fmt.Errorf("failed to update document with encrypted token: %w", err)
		}
	}

	tokens, err = s.decryptTokens(&tokens)
	if err != nil {
		s.logger.Error("Failed to decrypt tokens", zap.Int64("todoistUserID", todoistUserID), zap.Error(err))
		return User{}, false, fmt.Errorf("failed to decrypt tokens: %w", err)
	}
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

func (s *FirestoreTokenStore) DeleteTokensByPebbleAccount(ctx context.Context, pebbleAccountToken string) error {
	_, err := s.client.Collection(s.collectionName).Doc(pebbleAccountToken).Delete(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			s.logger.Info("No tokens found to delete for pebbleAccountToken", zap.String("pebbleAccountToken", pebbleAccountToken))
			return nil
		}
		s.logger.Error("Failed to delete tokens from Firestore", zap.String("pebbleAccountToken", pebbleAccountToken), zap.Error(err))
		return fmt.Errorf("failed to delete document: %w", err)
	}
	s.logger.Info("Successfully deleted tokens for pebbleAccountToken", zap.String("pebbleAccountToken", pebbleAccountToken))
	return nil
}

func (s *FirestoreTokenStore) Close() error {
	return s.client.Close()
}

func (s *FirestoreTokenStore) decryptTokens(tokens *User) (User, error) {
	if s.config.SecretKey != "" {
		if utils.IsEncrypted(tokens.PebbleTimelineToken, s.config.SecretKey) {
			decryptedToken, err := utils.Decrypt(tokens.PebbleTimelineToken, s.config.SecretKey)
			if err != nil {
				s.logger.Error("Failed to decrypt Pebble Timeline token", zap.Error(err))
				return User{}, fmt.Errorf("failed to decrypt Pebble Timeline token: %w", err)
			}
			tokens.PebbleTimelineToken = decryptedToken
		}
		if utils.IsEncrypted(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey) {
			decryptedToken, err := utils.Decrypt(tokens.TodoistAccessToken.AccessToken, s.config.SecretKey)
			if err != nil {
				s.logger.Error("Failed to decrypt Todoist access token", zap.Error(err))
				return User{}, fmt.Errorf("failed to decrypt Todoist access token: %w", err)
			}
			tokens.TodoistAccessToken.AccessToken = decryptedToken
		}
	}
	return *tokens, nil
}
