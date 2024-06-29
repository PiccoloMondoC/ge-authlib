// ge-auth/pkg/clientlib/authlib/password-change.go
package authlib

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// PasswordChange represents a single password change entry.
type PasswordChange struct {
	ChangeDate string `json:"change_date"`
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
}

// ChangePasswordInput represents the data required to change a password.
type ChangePasswordInput struct {
	UserID      string `json:"user_id"`
	NewPassword string `json:"new_password"`
}

// ChangePasswordOutput represents the data returned after successfully changing a password.
type ChangePasswordOutput struct {
	UserID string `json:"user_id"`
}

// ChangePassword sends a request to the change password endpoint and returns the response on success.
func (c *Client) ChangePassword(ctx context.Context, input ChangePasswordInput) (*ChangePasswordOutput, error) {
	changePasswordURL := fmt.Sprintf("%s/password/change", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, changePasswordURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to change password")
	}

	// Decode the response body
	var output ChangePasswordOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// LogPasswordChangeInput represents the data required to log a password change.
type LogPasswordChangeInput struct {
	UserID    string `json:"user_id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

// LogPasswordChange sends a request to the log password change endpoint and returns an error on failure.
func (c *Client) LogPasswordChange(ctx context.Context, input LogPasswordChangeInput) error {
	logPasswordChangeURL := fmt.Sprintf("%s/password/change/log", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, logPasswordChangeURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return errors.New("failed to log password change")
	}

	return nil
}

// GetPasswordChangeHistoryInput represents the data required to retrieve the password change history.
type GetPasswordChangeHistoryInput struct {
	UserID string `json:"user_id"`
}

// GetPasswordChangeHistoryOutput represents the data returned after retrieving the password change history.
type GetPasswordChangeHistoryOutput struct {
	UserID          string           `json:"user_id"`
	PasswordChanges []PasswordChange `json:"password_changes"`
}

// GetPasswordChangeHistory sends a request to the get password change history endpoint and returns the response on success.
func (c *Client) GetPasswordChangeHistory(ctx context.Context, input GetPasswordChangeHistoryInput) (*GetPasswordChangeHistoryOutput, error) {
	getPasswordChangeHistoryURL := fmt.Sprintf("%s/password/change/history", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, getPasswordChangeHistoryURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get password change history, status code: %d", resp.StatusCode)
	}

	// Decode the response body
	var output GetPasswordChangeHistoryOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// DeletePasswordChangeRecordsInput represents the data required to delete password change records.
type DeletePasswordChangeRecordsInput struct {
	UserID string `json:"user_id"`
}

// DeletePasswordChangeRecordsOutput represents the data returned after successfully deleting password change records.
type DeletePasswordChangeRecordsOutput struct {
	Success bool `json:"success"`
}

// DeletePasswordChangeRecords sends a request to the delete password change records endpoint and returns the response on success.
func (c *Client) DeletePasswordChangeRecords(ctx context.Context, input DeletePasswordChangeRecordsInput) (*DeletePasswordChangeRecordsOutput, error) {
	deletePasswordChangeRecordsURL := fmt.Sprintf("%s/password/change/records/delete", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deletePasswordChangeRecordsURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to delete password change records")
	}

	// Decode the response body
	var output DeletePasswordChangeRecordsOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}

// GetRecentPasswordChangeInput represents the data required to get the most recent password change.
type GetRecentPasswordChangeInput struct {
	UserID string `json:"user_id"`
}

// GetRecentPasswordChangeOutput represents the data returned after successfully getting the most recent password change.
type GetRecentPasswordChangeOutput struct {
	PasswordChange PasswordChange `json:"password_change"`
}

// GetRecentPasswordChange sends a request to the get recent password change endpoint and returns the response on success.
func (c *Client) GetRecentPasswordChange(ctx context.Context, input GetRecentPasswordChangeInput) (*GetRecentPasswordChangeOutput, error) {
	getRecentPasswordChangeURL := fmt.Sprintf("%s/password/change/recent", c.BaseURL)

	// Marshal the input into JSON
	reqBody, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, getRecentPasswordChangeURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.ApiKey))

	// Send the request
	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// If the response status is not 200, return an error
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to get recent password change")
	}

	// Decode the response body
	var output GetRecentPasswordChangeOutput
	if err := json.NewDecoder(resp.Body).Decode(&output); err != nil {
		return nil, fmt.Errorf("failed to decode response body: %w", err)
	}

	return &output, nil
}
