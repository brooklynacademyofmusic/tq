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

// PaymentPlanPreview payment plan preview
//
// swagger:model PaymentPlanPreview
type PaymentPlanPreview struct {

	// amount due
	AmountDue float64 `json:"AmountDue,omitempty"`

	// date due
	// Format: date-time
	DateDue strfmt.DateTime `json:"DateDue,omitempty"`
}

// Validate validates this payment plan preview
func (m *PaymentPlanPreview) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDateDue(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PaymentPlanPreview) validateDateDue(formats strfmt.Registry) error {
	if swag.IsZero(m.DateDue) { // not required
		return nil
	}

	if err := validate.FormatOf("DateDue", "body", "date-time", m.DateDue.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this payment plan preview based on context it is used
func (m *PaymentPlanPreview) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PaymentPlanPreview) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PaymentPlanPreview) UnmarshalBinary(b []byte) error {
	var res PaymentPlanPreview
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}