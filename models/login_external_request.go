// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// LoginExternalRequest login external request
//
// swagger:model LoginExternalRequest
type LoginExternalRequest struct {

	// login type Id
	LoginTypeID int32 `json:"LoginTypeId,omitempty"`

	// promotion code
	PromotionCode int32 `json:"PromotionCode,omitempty"`

	// user name
	UserName string `json:"UserName,omitempty"`
}

// Validate validates this login external request
func (m *LoginExternalRequest) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this login external request based on context it is used
func (m *LoginExternalRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LoginExternalRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LoginExternalRequest) UnmarshalBinary(b []byte) error {
	var res LoginExternalRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}