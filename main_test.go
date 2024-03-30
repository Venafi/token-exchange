package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_handleRequest(t *testing.T) {
	// Create a new request
	req, err := http.NewRequest(http.MethodPost, "/token", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Create a new response recorder
	rec := httptest.NewRecorder()

	// Call the handler function with the http recorder and request
	handleRequest(rec, req)

	// Check the status code
	if status := rec.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}

	// Check the response body
	expected := `{"token": "12345"}`
	if rec.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rec.Body.String(), expected)
	}
}
