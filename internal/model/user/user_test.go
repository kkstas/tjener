package user_test

import (
	"testing"

	"github.com/kkstas/tjener/internal/model/user"
)

const (
	firstName = "John"
	lastName  = "Doe"
	email     = "john@doe.com"
	password  = "newPassword123!"
)

func TestNew(t *testing.T) {
	t.Run("creates new user with hashed password", func(t *testing.T) {
		newUser, err := user.New(firstName, lastName, email, password)
		if err != nil {
			t.Fatalf("didn't expect an error but got one: %v", err)
		}
		assertEqual(t, newUser.FirstName, firstName)
		assertEqual(t, newUser.LastName, lastName)
		assertEqual(t, newUser.Email, email)
		assertEqual(t, user.CheckPassword(newUser.PasswordHash, password), true)
	})

	t.Run("returns error if name length is invalid", func(t *testing.T) {
		tooShortFirstName := string(make([]byte, user.FirstNameMinLength-1))
		tooLongFirstName := string(make([]byte, user.FirstNameMaxLength+1))
		tooShortLastName := string(make([]byte, user.LastNameMinLength-1))
		tooLongLastName := string(make([]byte, user.LastNameMaxLength+1))

		_, err := user.New(tooShortFirstName, lastName, email, password)
		if err == nil {
			t.Error("expected an error for too short first name but didn't get one")
		}
		_, err = user.New(tooLongFirstName, lastName, email, password)
		if err == nil {
			t.Error("expected an error for too long first name but didn't get one")
		}
		_, err = user.New(firstName, tooShortLastName, email, password)
		if err == nil {
			t.Error("expected an error for too short last name but didn't get one")
		}
		_, err = user.New(firstName, tooLongLastName, email, password)
		if err == nil {
			t.Error("expected an error for too long last name but didn't get one")
		}

	})
}

func assertEqual[T comparable](t testing.TB, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}
