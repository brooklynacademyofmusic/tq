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

// AuthorizationRequest authorization request
//
// swagger:model AuthorizationRequest
type AuthorizationRequest struct {

	// allow partial auth
	AllowPartialAuth bool `json:"AllowPartialAuth,omitempty"`

	// amount
	Amount float64 `json:"Amount,omitempty"`

	// authorization code
	AuthorizationCode string `json:"AuthorizationCode,omitempty"`

	// billing address
	BillingAddress *BillingAddress `json:"BillingAddress,omitempty"`

	// card
	Card *CardData `json:"Card,omitempty"`

	// constituent Id
	ConstituentID int32 `json:"ConstituentId,omitempty"`

	// delivery date
	// Format: date-time
	DeliveryDate *strfmt.DateTime `json:"DeliveryDate,omitempty"`

	// is e commerce
	IsECommerce bool `json:"IsECommerce,omitempty"`

	// is recurring
	IsRecurring bool `json:"IsRecurring,omitempty"`

	// payment Id
	PaymentID int32 `json:"PaymentId,omitempty"`

	// payment method Id
	PaymentMethodID int32 `json:"PaymentMethodId,omitempty"`

	// reference number
	ReferenceNumber string `json:"ReferenceNumber,omitempty"`

	// return Url
	ReturnURL string `json:"ReturnUrl,omitempty"`

	// shopper Ip
	ShopperIP string `json:"ShopperIp,omitempty"`

	// store account
	StoreAccount bool `json:"StoreAccount,omitempty"`

	// three d secure data
	ThreeDSecureData *ThreeDSecureData `json:"ThreeDSecureData,omitempty"`

	// transaction origin
	TransactionOrigin string `json:"TransactionOrigin,omitempty"`

	// user data
	UserData string `json:"UserData,omitempty"`
}

// Validate validates this authorization request
func (m *AuthorizationRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBillingAddress(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCard(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDeliveryDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateThreeDSecureData(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthorizationRequest) validateBillingAddress(formats strfmt.Registry) error {
	if swag.IsZero(m.BillingAddress) { // not required
		return nil
	}

	if m.BillingAddress != nil {
		if err := m.BillingAddress.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BillingAddress")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BillingAddress")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationRequest) validateCard(formats strfmt.Registry) error {
	if swag.IsZero(m.Card) { // not required
		return nil
	}

	if m.Card != nil {
		if err := m.Card.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Card")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Card")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationRequest) validateDeliveryDate(formats strfmt.Registry) error {
	if swag.IsZero(m.DeliveryDate) { // not required
		return nil
	}

	if err := validate.FormatOf("DeliveryDate", "body", "date-time", m.DeliveryDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AuthorizationRequest) validateThreeDSecureData(formats strfmt.Registry) error {
	if swag.IsZero(m.ThreeDSecureData) { // not required
		return nil
	}

	if m.ThreeDSecureData != nil {
		if err := m.ThreeDSecureData.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ThreeDSecureData")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ThreeDSecureData")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this authorization request based on the context it is used
func (m *AuthorizationRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBillingAddress(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCard(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateThreeDSecureData(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AuthorizationRequest) contextValidateBillingAddress(ctx context.Context, formats strfmt.Registry) error {

	if m.BillingAddress != nil {

		if swag.IsZero(m.BillingAddress) { // not required
			return nil
		}

		if err := m.BillingAddress.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BillingAddress")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BillingAddress")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationRequest) contextValidateCard(ctx context.Context, formats strfmt.Registry) error {

	if m.Card != nil {

		if swag.IsZero(m.Card) { // not required
			return nil
		}

		if err := m.Card.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Card")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Card")
			}
			return err
		}
	}

	return nil
}

func (m *AuthorizationRequest) contextValidateThreeDSecureData(ctx context.Context, formats strfmt.Registry) error {

	if m.ThreeDSecureData != nil {

		if swag.IsZero(m.ThreeDSecureData) { // not required
			return nil
		}

		if err := m.ThreeDSecureData.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ThreeDSecureData")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ThreeDSecureData")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AuthorizationRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AuthorizationRequest) UnmarshalBinary(b []byte) error {
	var res AuthorizationRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
