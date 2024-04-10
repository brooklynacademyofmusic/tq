// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// OrderProductViewPerformanceGroup order product view performance group
//
// swagger:model OrderProductViewPerformanceGroup
type OrderProductViewPerformanceGroup struct {

	// description
	Description string `json:"Description,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`
}

// Validate validates this order product view performance group
func (m *OrderProductViewPerformanceGroup) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this order product view performance group based on context it is used
func (m *OrderProductViewPerformanceGroup) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OrderProductViewPerformanceGroup) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OrderProductViewPerformanceGroup) UnmarshalBinary(b []byte) error {
	var res OrderProductViewPerformanceGroup
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}