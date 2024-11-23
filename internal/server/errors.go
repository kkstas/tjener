package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type APIError struct {
	Message    any `json:"message"`
	StatusCode int `json:"statusCode"`
}

func (e *APIError) Error() string {
	b, _ := json.Marshal(e)
	return string(b)
}

func NewAPIError(statusCode int, err error) *APIError {
	return &APIError{
		Message:    err.Error(),
		StatusCode: statusCode,
	}
}

func InvalidRequestData(errors map[string]string) APIError {
	return APIError{
		Message:    errors,
		StatusCode: http.StatusUnprocessableEntity,
	}
}

func InvalidJSON() *APIError {
	return NewAPIError(http.StatusBadRequest, fmt.Errorf("invalid JSON data"))
}

type APIFunc func(w http.ResponseWriter, r *http.Request) error

func (app *Application) make(h APIFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}

		var apiErr *APIError
		if errors.As(err, &apiErr) {
			if err := writeJSON(w, apiErr.StatusCode, apiErr); err != nil {
				app.logger.Error("failed encoding JSON", "error", err)
			} else {
				return
			}
		} else {
			app.logger.Error("APIFunc returned unknown error", "error", err)
		}

		_ = writeJSON(
			w,
			http.StatusInternalServerError,
			map[string]any{
				"message":    http.StatusInternalServerError,
				"statusCode": "Internal Server Error",
			},
		)
	}
}
