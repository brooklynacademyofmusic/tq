// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// TransferSessionRequest transfer session request
//
// swagger:model TransferSessionRequest
type TransferSessionRequest struct {

	// new session key
	NewSessionKey string `json:"NewSessionKey,omitempty"`
}

// Validate validates this transfer session request
func (m *TransferSessionRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this transfer session request based on context it is used
func (m *TransferSessionRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TransferSessionRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransferSessionRequest) UnmarshalBinary(b []byte) error {
	var res TransferSessionRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}