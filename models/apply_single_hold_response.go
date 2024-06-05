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

// ApplySingleHoldResponse apply single hold response
//
// swagger:model ApplySingleHoldResponse
type ApplySingleHoldResponse struct {

	// hold code Id
	HoldCodeID int32 `json:"HoldCodeId,omitempty"`

	// hold until date
	// Format: date-time
	HoldUntilDate *strfmt.DateTime `json:"HoldUntilDate,omitempty"`

	// performance Id
	PerformanceID int32 `json:"PerformanceId,omitempty"`

	// seat Id
	SeatID int32 `json:"SeatId,omitempty"`

	// seat status
	SeatStatus int32 `json:"SeatStatus,omitempty"`
}

// Validate validates this apply single hold response
func (m *ApplySingleHoldResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateHoldUntilDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ApplySingleHoldResponse) validateHoldUntilDate(formats strfmt.Registry) error {
	if swag.IsZero(m.HoldUntilDate) { // not required
		return nil
	}

	if err := validate.FormatOf("HoldUntilDate", "body", "date-time", m.HoldUntilDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this apply single hold response based on context it is used
func (m *ApplySingleHoldResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *ApplySingleHoldResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ApplySingleHoldResponse) UnmarshalBinary(b []byte) error {
	var res ApplySingleHoldResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
