// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CartPricingRuleSummary cart pricing rule summary
//
// swagger:model CartPricingRuleSummary
type CartPricingRuleSummary struct {

	// description
	Description string `json:"Description,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// rule action
	RuleAction int32 `json:"RuleAction,omitempty"`
}

// Validate validates this cart pricing rule summary
func (m *CartPricingRuleSummary) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this cart pricing rule summary based on context it is used
func (m *CartPricingRuleSummary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CartPricingRuleSummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CartPricingRuleSummary) UnmarshalBinary(b []byte) error {
	var res CartPricingRuleSummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}