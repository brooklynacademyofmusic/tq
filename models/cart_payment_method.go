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

// CartPaymentMethod cart payment method
//
// swagger:model CartPaymentMethod
type CartPaymentMethod struct {

	// account type
	AccountType *EntitySummary `json:"AccountType,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// payment type
	PaymentType *EntitySummary `json:"PaymentType,omitempty"`
}

// Validate validates this cart payment method
func (m *CartPaymentMethod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CartPaymentMethod) validateAccountType(formats strfmt.Registry) error {
	if swag.IsZero(m.AccountType) { // not required
		return nil
	}

	if m.AccountType != nil {
		if err := m.AccountType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AccountType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AccountType")
			}
			return err
		}
	}

	return nil
}

func (m *CartPaymentMethod) validatePaymentType(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentType) { // not required
		return nil
	}

	if m.PaymentType != nil {
		if err := m.PaymentType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PaymentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PaymentType")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this cart payment method based on the context it is used
func (m *CartPaymentMethod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePaymentType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CartPaymentMethod) contextValidateAccountType(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountType != nil {

		if swag.IsZero(m.AccountType) { // not required
			return nil
		}

		if err := m.AccountType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AccountType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AccountType")
			}
			return err
		}
	}

	return nil
}

func (m *CartPaymentMethod) contextValidatePaymentType(ctx context.Context, formats strfmt.Registry) error {

	if m.PaymentType != nil {

		if swag.IsZero(m.PaymentType) { // not required
			return nil
		}

		if err := m.PaymentType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PaymentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PaymentType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CartPaymentMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CartPaymentMethod) UnmarshalBinary(b []byte) error {
	var res CartPaymentMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}