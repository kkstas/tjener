package server

import (
	"net/http"
	"os"

	"github.com/kkstas/tjener/internal/auth"
	"github.com/kkstas/tjener/internal/model/user"
	"github.com/kkstas/tjener/internal/url"
)

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "origin-when-cross-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "deny")
		w.Header().Set("X-XSS-Protection", "0")
		next.ServeHTTP(w, r)
	})
}

func cacheControlMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		next.ServeHTTP(w, r)
	})
}

func redirectIfLoggedIn(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("token")
		if err == nil {
			_, err := auth.DecodeToken(token.Value)
			if err == nil {
				http.Redirect(w, r, url.Create(r.Context(), "home"), http.StatusFound)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (app *Application) toggleRegisterMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if os.Getenv("ENABLE_REGISTER") != "true" {
			http.Redirect(w, r, url.Create(r.Context(), "login"), http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (app *Application) withUser(fn func(http.ResponseWriter, *http.Request, user.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := r.Cookie("token")
		if err != nil || token.Value == "" {
			clearTokenCookie(w)
			http.Redirect(w, r, url.Create(r.Context(), "login"), http.StatusFound)
			return
		}

		cookieUser, err := auth.DecodeToken(token.Value)
		if err != nil {
			clearTokenCookie(w)
			http.Redirect(w, r, url.Create(r.Context(), "login"), http.StatusFound)
			return
		}

		fn(w, r, cookieUser)
	}
}
