/*
 *    Copyright 2025 blockarchitech
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may not use a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package handler

import (
	"net/http"
	"time"

	"blockarchitech.com/timetodo/internal/models"
	"blockarchitech.com/timetodo/internal/utils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	userContextKey = "user"
)

func (h *HttpHandlers) AuthMiddleware(fromPebble bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, span := h.Tracer.Start(c.Request.Context(), "AuthMiddleware")
		defer span.End()

		var pebbleAccountToken, pebbleTimelineToken string
		var err error

		if fromPebble {
			pebbleAccountToken, pebbleTimelineToken, err = h.AuthUtils.GetTokensFromPebbleHeaders(c.Request)
		} else {
			pebbleAccountToken, pebbleTimelineToken, err = h.AuthUtils.GetTokensFromHeader(c.Request)
		}

		if err != nil {
			h.logger.Warn("Missing or invalid authorization token", zap.Error(err))
			span.RecordError(err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		user, err := h.userRepo.GetByPebbleAccount(ctx, pebbleAccountToken)
		if err != nil {
			h.logger.Error("Failed to retrieve user", zap.Error(err), zap.String("pebbleAccountToken", pebbleAccountToken))
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve user"})
			return
		}

		if user == nil {
			h.logger.Warn("User not found", zap.String("pebbleAccountToken", pebbleAccountToken))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if fromPebble && user.PebbleTimelineToken != pebbleTimelineToken {
			h.logger.Warn("Timeline token mismatch", zap.String("pebbleAccountToken", pebbleAccountToken))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if user.TodoistAccessToken.AccessToken == "" {
			h.logger.Warn("Todoist access token is missing for user", zap.String("pebbleAccountToken", pebbleAccountToken))
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set(userContextKey, user)
		c.Next()
	}
}

func (h *HttpHandlers) LoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)
		h.logger.Info("request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", latency),
			zap.String("ip", c.ClientIP()),
		)
	}
}

func (h *HttpHandlers) CORSMiddleware() gin.HandlerFunc {
	allowed := make(map[string]struct{})
	for _, o := range utils.SplitAndTrim(h.config.CORSAllowedOrigins, ",") {
		if o != "" {
			allowed[o] = struct{}{}
		}
	}
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			if _, ok := allowed[origin]; ok || origin == "null" {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Vary", "Origin")
				c.Header("Access-Control-Allow-Credentials", "true")
				c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
				c.Header("Access-Control-Allow-Headers", "Authorization,Content-Type,X-CSRF-Token")
				c.Header("Access-Control-Max-Age", "600")
			}
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (h *HttpHandlers) CSRFMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := c.Cookie("ttd_csrf")
		if err != nil || token == "" {
			util := utils.NewAuthUtils()
			s, genErr := util.GenerateOAuthState()
			if genErr == nil {
				secure := c.Request.TLS != nil || c.Request.Header.Get("X-Forwarded-Proto") == "https"
				c.SetCookie("ttd_csrf", s, 3600, "/", "", secure, false)
				token = s
			}
		}

		p := c.Request.URL.Path
		if c.Request.Method == http.MethodGet || c.Request.Method == http.MethodHead || c.Request.Method == http.MethodOptions ||
			p == "/api/v1/todoist/callback" || p == "/api/v1/todoist/webhook" || p == "/api/v1/pebble/action" || p == "/healthz" || p == "/robots.txt" || p == "/auth/delete" {
			c.Next()
			return
		}

		h := c.Request.Header.Get("X-CSRF-Token")
		if h == "" || h != token {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "CSRF token invalid"})
			return
		}
		c.Next()
	}
}

func GetUserFromContext(c *gin.Context) (*models.User, bool) {
	user, exists := c.Get(userContextKey)
	if !exists {
		return nil, false
	}
	userModel, ok := user.(*models.User)
	return userModel, ok
}
