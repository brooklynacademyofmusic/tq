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

// EmailPromotionUpdateRequest email promotion update request
//
// swagger:model EmailPromotionUpdateRequest
type EmailPromotionUpdateRequest struct {

	// constituent Id
	ConstituentID int32 `json:"ConstituentId,omitempty"`

	// download number
	DownloadNumber int32 `json:"DownloadNumber,omitempty"`

	// event date time
	// Format: date-time
	EventDateTime *strfmt.DateTime `json:"EventDateTime,omitempty"`

	// event name
	EventName string `json:"EventName,omitempty"`
}

// Validate validates this email promotion update request
func (m *EmailPromotionUpdateRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEventDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EmailPromotionUpdateRequest) validateEventDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.EventDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("EventDateTime", "body", "date-time", m.EventDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this email promotion update request based on context it is used
func (m *EmailPromotionUpdateRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EmailPromotionUpdateRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EmailPromotionUpdateRequest) UnmarshalBinary(b []byte) error {
	var res EmailPromotionUpdateRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}