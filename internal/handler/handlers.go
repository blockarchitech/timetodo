/*
 * Copyright 2025 blockarchitech
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package handler

import (
	"blockarchitech.com/timetodo/internal/config"
	"blockarchitech.com/timetodo/internal/repository"
	"blockarchitech.com/timetodo/internal/service"
	"blockarchitech.com/timetodo/internal/utils"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// HttpHandlers holds application-wide state and dependencies.
type HttpHandlers struct {
	logger                *zap.Logger
	userRepo              repository.UserRepository
	oauth2Config          *oauth2.Config
	config                *config.Config
	pebbleTimelineService *service.PebbleTimelineService
	todoistService        *service.TodoistService
	Tracer                trace.Tracer
	TodoistUtils          *utils.TodoistUtils
	PebbleUtils           *utils.PebbleUtils
	AuthUtils             *utils.AuthUtils
}

// NewHttpHandlers creates a new HttpHandlers instance.
func NewHttpHandlers(
	logger *zap.Logger,
	oauth2Config *oauth2.Config,
	userRepo repository.UserRepository,
	cfg *config.Config,
	todoistService *service.TodoistService,
	pebbleService *service.PebbleTimelineService,
	tracer trace.Tracer,
) *HttpHandlers {
	return &HttpHandlers{
		logger:                logger.Named("http_handler"),
		userRepo:              userRepo,
		oauth2Config:          oauth2Config,
		config:                cfg,
		pebbleTimelineService: pebbleService,
		todoistService:        todoistService,
		Tracer:                tracer,
		TodoistUtils:          utils.NewTodoistUtils(cfg, logger.Named("todoist_utils")),
		PebbleUtils:           utils.NewPebbleUtils(logger.Named("pebble_utils"), cfg),
		AuthUtils:             utils.NewAuthUtils(),
	}
}
