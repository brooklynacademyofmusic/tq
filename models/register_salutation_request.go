// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// RegisterSalutationRequest register salutation request
//
// swagger:model RegisterSalutationRequest
type RegisterSalutationRequest struct {

	// business title
	BusinessTitle string `json:"BusinessTitle,omitempty"`

	// envelope salutation1
	EnvelopeSalutation1 string `json:"EnvelopeSalutation1,omitempty"`

	// envelope salutation2
	EnvelopeSalutation2 string `json:"EnvelopeSalutation2,omitempty"`

	// letter salutation
	LetterSalutation string `json:"LetterSalutation,omitempty"`

	// salutation type Id
	SalutationTypeID int32 `json:"SalutationTypeId,omitempty"`
}

// Validate validates this register salutation request
func (m *RegisterSalutationRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this register salutation request based on context it is used
func (m *RegisterSalutationRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *RegisterSalutationRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *RegisterSalutationRequest) UnmarshalBinary(b []byte) error {
	var res RegisterSalutationRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}