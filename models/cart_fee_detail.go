// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// CartFeeDetail cart fee detail
//
// swagger:model CartFeeDetail
type CartFeeDetail struct {

	// amount
	Amount float64 `json:"Amount,omitempty"`

	// db status
	DbStatus int32 `json:"DbStatus,omitempty"`

	// fee summary
	FeeSummary *CartFeeSummary `json:"FeeSummary,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// line item Id
	LineItemID int32 `json:"LineItemId,omitempty"`

	// override amount
	OverrideAmount float64 `json:"OverrideAmount,omitempty"`

	// override indicator
	OverrideIndicator string `json:"OverrideIndicator,omitempty"`

	// sub line item Id
	SubLineItemID int32 `json:"SubLineItemId,omitempty"`
}

// Validate validates this cart fee detail
func (m *CartFeeDetail) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateFeeSummary(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CartFeeDetail) validateFeeSummary(formats strfmt.Registry) error {
	if swag.IsZero(m.FeeSummary) { // not required
		return nil
	}

	if m.FeeSummary != nil {
		if err := m.FeeSummary.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("FeeSummary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("FeeSummary")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this cart fee detail based on the context it is used
func (m *CartFeeDetail) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateFeeSummary(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CartFeeDetail) contextValidateFeeSummary(ctx context.Context, formats strfmt.Registry) error {

	if m.FeeSummary != nil {

		if swag.IsZero(m.FeeSummary) { // not required
			return nil
		}

		if err := m.FeeSummary.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("FeeSummary")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("FeeSummary")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CartFeeDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CartFeeDetail) UnmarshalBinary(b []byte) error {
	var res CartFeeDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}