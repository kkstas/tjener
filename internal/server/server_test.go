package server_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kkstas/tjener/internal/model"
	"github.com/kkstas/tjener/internal/server"
)

func TestHomeHandler(t *testing.T) {
	t.Run("responds with html", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/home", nil)
		newTestApplication().ServeHTTP(response, request)

		assertStatus(t, response.Code, http.StatusOK)

		contentType := response.Header().Get("content-type")
		if !strings.HasPrefix(contentType, "text/html") {
			t.Errorf("invalid content type %q", contentType)
		}
	})
}

func TestHealthCheck(t *testing.T) {
	t.Run("returns status 200", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/health-check", nil)
		newTestApplication().ServeHTTP(response, request)

		assertStatus(t, response.Code, http.StatusOK)
	})
}

func TestStaticCss(t *testing.T) {
	t.Run("returns css file content with status 200", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/assets/public/css/out.css", nil)
		newTestApplication().ServeHTTP(response, request)

		assertStatus(t, response.Code, http.StatusOK)

		if response.Body.Len() == 0 {
			t.Errorf("response body is empty")
		}
	})
}

func TestNotFoundHandler(t *testing.T) {
	s := newTestApplication()

	cases := []struct {
		method string
		target string
	}{
		{http.MethodGet, "/"},
		{http.MethodPost, "/"},
		{http.MethodPut, "/"},
		{http.MethodPatch, "/"},
		{http.MethodDelete, "/"},
		{http.MethodGet, "/abcd1234"},
		{http.MethodPost, "/abcd1234"},
		{http.MethodPut, "/abcd1234"},
		{http.MethodPatch, "/abcd1234"},
		{http.MethodDelete, "/abcd1234"},
	}

	for _, want := range cases {
		t.Run(fmt.Sprintf("responds with 404 for '%s %s'", want.method, want.target), func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(want.method, want.target, nil)
			s.ServeHTTP(response, request)
			assertStatus(t, response.Code, http.StatusNotFound)
		})
	}
}

func TestCreateExpense(t *testing.T) {
	t.Run("returns 400 if there's no form params", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/expense/create", nil)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		newTestApplication().ServeHTTP(response, request)
		assertStatus(t, response.Code, http.StatusBadRequest)
	})

	t.Run("returns 400 if amount is not valid float64", func(t *testing.T) {
		var param = url.Values{}
		param.Set("currency", "PLN")
		param.Set("amount", "1.9d9")
		param.Set("category", "food")
		var payload = bytes.NewBufferString(param.Encode())

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/expense/create", payload)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		newTestApplication().ServeHTTP(response, request)

		assertStatus(t, response.Code, http.StatusBadRequest)
	})

	t.Run("returns 201 with html", func(t *testing.T) {
		var param = url.Values{}
		param.Set("currency", "PLN")
		param.Set("amount", "1.99")
		param.Set("category", "food")
		param.Set("name", "some name")
		var payload = bytes.NewBufferString(param.Encode())

		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/expense/create", payload)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		newTestApplication().ServeHTTP(response, request)
		assertStatus(t, response.Code, http.StatusSeeOther)
	})
}

func TestShowExpense(t *testing.T) {
	t.Run("returns 404 if there's no found expense", func(t *testing.T) {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/expense/x", nil)
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		newTestApplication().ServeHTTP(response, request)
		assertStatus(t, response.Code, http.StatusNotFound)
	})
}

func assertStatus(t testing.TB, got, want int) {
	t.Helper()
	if got != want {
		t.Errorf("did not get correct status: got %d, want %d", got, want)
	}
}

func newTestApplication() *server.Application {
	return server.NewApplication(&model.ExpenseInMemoryStore{}, &model.ExpenseCategoryInMemoryStore{})
}
