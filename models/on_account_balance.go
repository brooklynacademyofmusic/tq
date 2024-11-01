// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OnAccountBalance on account balance
//
// swagger:model OnAccountBalance
type OnAccountBalance struct {

	// balance
	Balance float64 `json:"Balance,omitempty"`

	// constituent Id
	ConstituentID int32 `json:"ConstituentId,omitempty"`

	// current balance
	CurrentBalance float64 `json:"CurrentBalance,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// payment method Id
	PaymentMethodID int32 `json:"PaymentMethodId,omitempty"`

	// used in session
	UsedInSession float64 `json:"UsedInSession,omitempty"`
}

// Validate validates this on account balance
func (m *OnAccountBalance) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this on account balance based on context it is used
func (m *OnAccountBalance) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OnAccountBalance) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OnAccountBalance) UnmarshalBinary(b []byte) error {
	var res OnAccountBalance
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}