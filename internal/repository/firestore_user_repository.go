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
	"time"

	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/models"
	"blockarchitech.com/timetodo/internal/utils"
	"cloud.google.com/go/firestore"
	"go.uber.org/zap"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const userCollection = "users"

// FirestoreUserRepository is a Firestore implementation of the UserRepository.
type FirestoreUserRepository struct {
	client *firestore.Client
	logger *zap.Logger
	config *config.Config
}

// NewFirestoreUserRepository creates a new FirestoreUserRepository.
func NewFirestoreUserRepository(ctx context.Context, projectID string, logger *zap.Logger, config *config.Config) (*FirestoreUserRepository, error) {
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to create firestore client: %w", err)
	}
	return &FirestoreUserRepository{
		client: client,
		logger: logger.Named("firestore_user_repo"),
		config: config,
	}, nil
}

func (r *FirestoreUserRepository) Create(ctx context.Context, user *models.User) error {
	user.LastUpdated = time.Now()
	encryptedUser, err := r.encryptUser(user)
	if err != nil {
		return err
	}
	_, err = r.client.Collection(userCollection).Doc(user.PebbleAccountToken).Set(ctx, encryptedUser)
	if err != nil {
		return fmt.Errorf("failed to create user in firestore: %w", err)
	}
	r.logger.Info("Created user in Firestore", zap.String("pebbleAccountToken", user.PebbleAccountToken))
	return nil
}

func (r *FirestoreUserRepository) GetByPebbleAccount(ctx context.Context, pebbleAccountToken string) (*models.User, error) {
	doc, err := r.client.Collection(userCollection).Doc(pebbleAccountToken).Get(ctx)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get user by pebble account: %w", err)
	}
	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %w", err)
	}
	return r.decryptUser(&user)
}

func (r *FirestoreUserRepository) GetByTodoistUserID(ctx context.Context, todoistUserID int64) (*models.User, error) {
	iter := r.client.Collection(userCollection).Where("todoistUserID", "==", todoistUserID).Limit(1).Documents(ctx)
	defer iter.Stop()
	doc, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			return nil, nil // Not found
		}
		return nil, fmt.Errorf("failed to get user by todoist id: %w", err)
	}
	var user models.User
	if err := doc.DataTo(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user data: %w", err)
	}
	return r.decryptUser(&user)
}

func (r *FirestoreUserRepository) Update(ctx context.Context, user *models.User) error {
	user.LastUpdated = time.Now()
	encryptedUser, err := r.encryptUser(user)
	if err != nil {
		return err
	}
	_, err = r.client.Collection(userCollection).Doc(user.PebbleAccountToken).Set(ctx, encryptedUser)
	if err != nil {
		return fmt.Errorf("failed to update user in firestore: %w", err)
	}
	r.logger.Info("Updated user in Firestore", zap.String("pebbleAccountToken", user.PebbleAccountToken))
	return nil
}

func (r *FirestoreUserRepository) DeleteByPebbleAccount(ctx context.Context, pebbleAccountToken string) error {
	_, err := r.client.Collection(userCollection).Doc(pebbleAccountToken).Delete(ctx)
	if err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("failed to delete user by pebble account: %w", err)
	}
	r.logger.Info("Deleted user by pebble account from Firestore", zap.String("pebbleAccountToken", pebbleAccountToken))
	return nil
}

func (r *FirestoreUserRepository) DeleteByTodoistUserID(ctx context.Context, todoistUserID int64) error {
	iter := r.client.Collection(userCollection).Where("todoistUserID", "==", todoistUserID).Limit(1).Documents(ctx)
	defer iter.Stop()
	doc, err := iter.Next()
	if err != nil {
		if errors.Is(err, iterator.Done) {
			return nil // Not found, nothing to delete
		}
		return fmt.Errorf("failed to find user by todoist id for deletion: %w", err)
	}
	_, err = doc.Ref.Delete(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete user by todoist id: %w", err)
	}
	r.logger.Info("Deleted user by todoist ID from Firestore", zap.Int64("todoistUserID", todoistUserID))
	return nil
}

func (r *FirestoreUserRepository) UpdateUserPreferences(ctx context.Context, pebbleAccountToken string, prefs models.Preferences) error {
	docRef := r.client.Collection(userCollection).Doc(pebbleAccountToken)
	_, err := docRef.Update(ctx, []firestore.Update{
		{Path: "preferences", Value: prefs},
	})
	if err != nil {
		return fmt.Errorf("failed to update user preferences: %w", err)
	}
	return nil
}

func (r *FirestoreUserRepository) Close() error {
	return r.client.Close()
}

// encryptUser encrypts sensitive fields in the User struct.
func (r *FirestoreUserRepository) encryptUser(user *models.User) (*models.User, error) {
	if r.config.SecretKey == "" {
		return user, nil
	}
	encrypted := *user
	var err error
	if encrypted.PebbleTimelineToken != "" {
		encrypted.PebbleTimelineToken, err = utils.Encrypt(encrypted.PebbleTimelineToken, r.config.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt pebble timeline token: %w", err)
		}
	}
	if encrypted.TodoistAccessToken != nil && encrypted.TodoistAccessToken.AccessToken != "" {
		encrypted.TodoistAccessToken.AccessToken, err = utils.Encrypt(encrypted.TodoistAccessToken.AccessToken, r.config.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt todoist access token: %w", err)
		}
	}
	return &encrypted, nil
}

// decryptUser decrypts sensitive fields in the User struct.
func (r *FirestoreUserRepository) decryptUser(user *models.User) (*models.User, error) {
	if r.config.SecretKey == "" {
		return user, nil
	}
	decrypted := *user
	var err error
	if decrypted.PebbleTimelineToken != "" {
		decrypted.PebbleTimelineToken, err = utils.Decrypt(decrypted.PebbleTimelineToken, r.config.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt pebble timeline token: %w", err)
		}
	}
	if decrypted.TodoistAccessToken != nil && decrypted.TodoistAccessToken.AccessToken != "" {
		decrypted.TodoistAccessToken.AccessToken, err = utils.Decrypt(decrypted.TodoistAccessToken.AccessToken, r.config.SecretKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt todoist access token: %w", err)
		}
	}
	return &decrypted, nil
}
