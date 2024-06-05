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

// CheckoutWithCardRequest checkout with card request
//
// swagger:model CheckoutWithCardRequest
type CheckoutWithCardRequest struct {

	// allow under payment
	AllowUnderPayment bool `json:"AllowUnderPayment,omitempty"`

	// amount
	Amount float64 `json:"Amount,omitempty"`

	// authorization code
	AuthorizationCode string `json:"AuthorizationCode,omitempty"`

	// authorize
	Authorize bool `json:"Authorize,omitempty"`

	// credit card track1
	CreditCardTrack1 string `json:"CreditCardTrack1,omitempty"`

	// credit card track2
	CreditCardTrack2 string `json:"CreditCardTrack2,omitempty"`

	// credit card type
	CreditCardType int32 `json:"CreditCardType,omitempty"`

	// delivery date
	// Format: date-time
	DeliveryDate *strfmt.DateTime `json:"DeliveryDate,omitempty"`

	// e commerce
	ECommerce bool `json:"ECommerce,omitempty"`

	// store account
	StoreAccount bool `json:"StoreAccount,omitempty"`

	// zip code
	ZipCode string `json:"ZipCode,omitempty"`
}

// Validate validates this checkout with card request
func (m *CheckoutWithCardRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDeliveryDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CheckoutWithCardRequest) validateDeliveryDate(formats strfmt.Registry) error {
	if swag.IsZero(m.DeliveryDate) { // not required
		return nil
	}

	if err := validate.FormatOf("DeliveryDate", "body", "date-time", m.DeliveryDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this checkout with card request based on context it is used
func (m *CheckoutWithCardRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CheckoutWithCardRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CheckoutWithCardRequest) UnmarshalBinary(b []byte) error {
	var res CheckoutWithCardRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
