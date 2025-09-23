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

package handler

import "github.com/gin-gonic/gin"

// Route constants centralize HTTP paths for easier maintenance and consistency.

func (h *HttpHandlers) RegisterRoutes(router *gin.Engine) {
	// Group routes for better organization

	router.Use(h.LoggerMiddleware())
	router.Use(h.CORSMiddleware())
	router.Use(h.CSRFMiddleware())

	v1 := router.Group("/api/v1")
	{
		me := v1.Group("/me")
		me.Use(h.AuthMiddleware(false))
		{
			me.GET("", h.HandleGetMe)
			me.POST("", h.HandleUpdateMe)
			me.DELETE("", h.HandleDeleteMe)
		}

		todoist := v1.Group("/todoist")
		{
			todoist.GET("/login", h.HandleTodoistLogin)
			todoist.GET("/callback", h.HandleTodoistCallback)
			todoist.POST("/webhook", h.HandleTodoistWebhook)
		}

		pebble := v1.Group("/pebble")
		{
			pebble.POST("/action", h.AuthMiddleware(true), h.HandlePebbleAction)
		}
	}

	router.GET("/auth/delete", h.HandleDeletePage)

	// Serve the app
	router.Static("/assets", "public/assets")
	router.GET("/config", h.ServeApp())
}
