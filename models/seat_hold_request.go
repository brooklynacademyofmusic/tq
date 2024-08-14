// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SeatHoldRequest seat hold request
//
// swagger:model SeatHoldRequest
type SeatHoldRequest struct {

	// hold code Id
	HoldCodeID int32 `json:"HoldCodeId,omitempty"`

	// seat Id
	SeatID int32 `json:"SeatId,omitempty"`
}

// Validate validates this seat hold request
func (m *SeatHoldRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this seat hold request based on context it is used
func (m *SeatHoldRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SeatHoldRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SeatHoldRequest) UnmarshalBinary(b []byte) error {
	var res SeatHoldRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}