// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// PriceEventMoveRequest price event move request
//
// swagger:model PriceEventMoveRequest
type PriceEventMoveRequest struct {

	// event date time
	// Format: date-time
	EventDateTime *strfmt.DateTime `json:"EventDateTime,omitempty"`

	// event ids
	EventIds string `json:"EventIds,omitempty"`
}

// Validate validates this price event move request
func (m *PriceEventMoveRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEventDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PriceEventMoveRequest) validateEventDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.EventDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("EventDateTime", "body", "date-time", m.EventDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this price event move request based on context it is used
func (m *PriceEventMoveRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PriceEventMoveRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PriceEventMoveRequest) UnmarshalBinary(b []byte) error {
	var res PriceEventMoveRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
