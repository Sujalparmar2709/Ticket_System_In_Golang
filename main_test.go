package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealth(t *testing.T) {
	server := newServer("test-secret")
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	server.routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("expected ok status, got %#v", payload)
	}
}

func TestAuthAndTicketFlow(t *testing.T) {
	server := newServer("test-secret")

	registerBody := bytes.NewBufferString(`{"email":"a@example.com","password":"secret","name":"A"}`)
	registerReq := httptest.NewRequest(http.MethodPost, "/auth/register", registerBody)
	registerReq.Header.Set("Content-Type", "application/json")
	registerRec := httptest.NewRecorder()
	server.routes().ServeHTTP(registerRec, registerReq)
	if registerRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d", registerRec.Code)
	}

	loginBody := bytes.NewBufferString(`{"email":"a@example.com","password":"secret"}`)
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", loginBody)
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	server.routes().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d", loginRec.Code)
	}

	var loginPayload map[string]string
	if err := json.NewDecoder(loginRec.Body).Decode(&loginPayload); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	token := loginPayload["token"]
	if token == "" {
		t.Fatal("missing token")
	}

	headers := map[string]string{"Authorization": "Bearer " + token}
	createReq := httptest.NewRequest(http.MethodPost, "/tickets", bytes.NewBufferString(`{"title":"First","description":"Demo"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", headers["Authorization"])
	createRec := httptest.NewRecorder()
	server.routes().ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d", createRec.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/tickets", nil)
	listReq.Header.Set("Authorization", headers["Authorization"])
	listRec := httptest.NewRecorder()
	server.routes().ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRec.Code)
	}

	var tickets []Ticket
	if err := json.NewDecoder(listRec.Body).Decode(&tickets); err != nil {
		t.Fatalf("decode tickets: %v", err)
	}
	if len(tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(tickets))
	}
	if tickets[0].Status != statusOpen {
		t.Fatalf("expected open ticket, got %s", tickets[0].Status)
	}

	updateReq := httptest.NewRequest(http.MethodPatch, "/tickets/1/status", bytes.NewBufferString(`{"status":"in_progress"}`))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", headers["Authorization"])
	updateRec := httptest.NewRecorder()
	server.routes().ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d", updateRec.Code)
	}

	var updated Ticket
	if err := json.NewDecoder(updateRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode updated ticket: %v", err)
	}
	if updated.Status != statusInProgress {
		t.Fatalf("expected in_progress, got %s", updated.Status)
	}
}

func TestClosedTicketCannotReopen(t *testing.T) {
	server := newServer("test-secret")
	registerAndLogin := func() string {
		registerReq := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(`{"email":"b@example.com","password":"secret"}`))
		registerReq.Header.Set("Content-Type", "application/json")
		registerRec := httptest.NewRecorder()
		server.routes().ServeHTTP(registerRec, registerReq)

		loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"b@example.com","password":"secret"}`))
		loginReq.Header.Set("Content-Type", "application/json")
		loginRec := httptest.NewRecorder()
		server.routes().ServeHTTP(loginRec, loginReq)

		var loginPayload map[string]string
		if err := json.NewDecoder(loginRec.Body).Decode(&loginPayload); err != nil {
			t.Fatalf("decode login token: %v", err)
		}
		return loginPayload["token"]
	}

	token := registerAndLogin()
	header := "Bearer " + token

	createReq := httptest.NewRequest(http.MethodPost, "/tickets", bytes.NewBufferString(`{"title":"Flow"}`))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", header)
	createRec := httptest.NewRecorder()
	server.routes().ServeHTTP(createRec, createReq)

	closeReq := httptest.NewRequest(http.MethodPatch, "/tickets/1/status", bytes.NewBufferString(`{"status":"in_progress"}`))
	closeReq.Header.Set("Content-Type", "application/json")
	closeReq.Header.Set("Authorization", header)
	closeRec := httptest.NewRecorder()
	server.routes().ServeHTTP(closeRec, closeReq)

	finalReq := httptest.NewRequest(http.MethodPatch, "/tickets/1/status", bytes.NewBufferString(`{"status":"closed"}`))
	finalReq.Header.Set("Content-Type", "application/json")
	finalReq.Header.Set("Authorization", header)
	finalRec := httptest.NewRecorder()
	server.routes().ServeHTTP(finalRec, finalReq)
	if finalRec.Code != http.StatusOK {
		t.Fatalf("close status = %d", finalRec.Code)
	}

	reopenReq := httptest.NewRequest(http.MethodPatch, "/tickets/1/status", bytes.NewBufferString(`{"status":"open"}`))
	reopenReq.Header.Set("Content-Type", "application/json")
	reopenReq.Header.Set("Authorization", header)
	reopenRec := httptest.NewRecorder()
	server.routes().ServeHTTP(reopenRec, reopenReq)
	if reopenRec.Code != http.StatusBadRequest {
		t.Fatalf("reopen status = %d", reopenRec.Code)
	}
}
