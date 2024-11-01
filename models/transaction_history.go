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

// TransactionHistory transaction history
//
// swagger:model TransactionHistory
type TransactionHistory struct {

	// adjusted reason description
	AdjustedReasonDescription string `json:"AdjustedReasonDescription,omitempty"`

	// appeal description
	AppealDescription string `json:"AppealDescription,omitempty"`

	// batch Id
	BatchID int32 `json:"BatchId,omitempty"`

	// campaign description
	CampaignDescription string `json:"CampaignDescription,omitempty"`

	// constituent Id
	ConstituentID int32 `json:"ConstituentId,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// fund description
	FundDescription string `json:"FundDescription,omitempty"`

	// media type description
	MediaTypeDescription string `json:"MediaTypeDescription,omitempty"`

	// post Id
	PostID int32 `json:"PostId,omitempty"`

	// reference Id
	ReferenceID int32 `json:"ReferenceId,omitempty"`

	// source
	Source string `json:"Source,omitempty"`

	// transaction amount
	TransactionAmount float64 `json:"TransactionAmount,omitempty"`

	// transaction date time
	// Format: date-time
	TransactionDateTime *strfmt.DateTime `json:"TransactionDateTime,omitempty"`

	// transaction Id
	TransactionID int32 `json:"TransactionId,omitempty"`

	// transaction type description
	TransactionTypeDescription string `json:"TransactionTypeDescription,omitempty"`
}

// Validate validates this transaction history
func (m *TransactionHistory) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTransactionDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TransactionHistory) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *TransactionHistory) validateTransactionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.TransactionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("TransactionDateTime", "body", "date-time", m.TransactionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this transaction history based on context it is used
func (m *TransactionHistory) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *TransactionHistory) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TransactionHistory) UnmarshalBinary(b []byte) error {
	var res TransactionHistory
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}