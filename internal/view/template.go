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

package view

import (
	"html/template"
	"io/fs"
	"net/http"
	"path/filepath"

	"go.uber.org/zap"
)

// HTMLTemplateManager manages HTML templates.
type HTMLTemplateManager struct {
	logger    *zap.Logger
	templates map[string]*template.Template
}

// NewHTMLTemplateManager creates a new HTMLTemplateManager and parses templates
// from the given directory.
func NewHTMLTemplateManager(logger *zap.Logger, dir string) (*HTMLTemplateManager, error) {
	m := &HTMLTemplateManager{
		logger:    logger.Named("html_template_manager"),
		templates: make(map[string]*template.Template),
	}

	pages, err := filepath.Glob(filepath.Join(dir, "*.html"))
	if err != nil {
		m.logger.Error("Failed to glob for HTML templates", zap.String("directory", dir), zap.Error(err))
		return nil, err
	}

	for _, page := range pages {
		name := filepath.Base(page)
		tmpl, err := template.New(name).ParseFiles(page)
		if err != nil {
			m.logger.Error("Failed to parse HTML template", zap.String("template_file", page), zap.Error(err))
			return nil, err
		}
		m.templates[name] = tmpl
		m.logger.Debug("Successfully parsed template", zap.String("template_name", name))
	}

	m.logger.Info("HTML templates loaded successfully", zap.Int("count", len(m.templates)), zap.String("directory", dir))
	return m, nil
}

// Render executes the named template with the given data and writes to the ResponseWriter.
func (m *HTMLTemplateManager) Render(w http.ResponseWriter, name string, data interface{}) error {
	tmpl, ok := m.templates[name]
	if !ok {
		m.logger.Error("Template not found", zap.String("template_name", name))
		return fs.ErrNotExist // Or a more specific error
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err := tmpl.ExecuteTemplate(w, name, data)
	if err != nil {
		m.logger.Error("Failed to render template", zap.String("template_name", name), zap.Error(err))
		return err
	}
	return nil
}
