// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// PricingRuleCategorySummary pricing rule category summary
//
// swagger:model PricingRuleCategorySummary
type PricingRuleCategorySummary struct {

	// description
	Description string `json:"Description,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`
}

// Validate validates this pricing rule category summary
func (m *PricingRuleCategorySummary) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this pricing rule category summary based on context it is used
func (m *PricingRuleCategorySummary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PricingRuleCategorySummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PricingRuleCategorySummary) UnmarshalBinary(b []byte) error {
	var res PricingRuleCategorySummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}