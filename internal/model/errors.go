package model

import (
	"fmt"
)

type ExpenseCategoryIsTooShortError struct {
	Name string
}

func (e *ExpenseCategoryIsTooShortError) Error() string {
	return fmt.Sprintf("expense category '%s' is too short", e.Name)
}

type ExpenseAmountIsZeroError struct{}

func (e *ExpenseAmountIsZeroError) Error() string {
	return "expense amount cannot be zero"
}

type InvalidCurrencyError struct {
	Currency string
}

func (e *InvalidCurrencyError) Error() string {
	return fmt.Sprintf("currency '%s' is invalid", e.Currency)
}

type InvalidAmountPrecisionError struct {
	Amount float64
}

func (e *InvalidAmountPrecisionError) Error() string {
	return fmt.Sprintf("amount '%f' has too large precision", e.Amount)
}

type ExpenseNotFoundError struct {
	PK string
	SK string
}

func (e *ExpenseNotFoundError) Error() string {
	return fmt.Sprintf("no item found with PK: %v, SK: %v", e.PK, e.SK)
}