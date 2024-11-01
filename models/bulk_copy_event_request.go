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

// BulkCopyEventRequest bulk copy event request
//
// swagger:model BulkCopyEventRequest
type BulkCopyEventRequest struct {

	// copy to date
	// Format: date-time
	CopyToDate *strfmt.DateTime `json:"CopyToDate,omitempty"`

	// performance code counter
	PerformanceCodeCounter int32 `json:"PerformanceCodeCounter,omitempty"`
}

// Validate validates this bulk copy event request
func (m *BulkCopyEventRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCopyToDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BulkCopyEventRequest) validateCopyToDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CopyToDate) { // not required
		return nil
	}

	if err := validate.FormatOf("CopyToDate", "body", "date-time", m.CopyToDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this bulk copy event request based on context it is used
func (m *BulkCopyEventRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *BulkCopyEventRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BulkCopyEventRequest) UnmarshalBinary(b []byte) error {
	var res BulkCopyEventRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}