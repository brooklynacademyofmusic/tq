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

// PaymentAvailableForRefund payment available for refund
//
// swagger:model PaymentAvailableForRefund
type PaymentAvailableForRefund struct {

	// account Id
	AccountID int32 `json:"AccountId,omitempty"`

	// account last four
	AccountLastFour string `json:"AccountLastFour,omitempty"`

	// available for refund amount
	AvailableForRefundAmount float64 `json:"AvailableForRefundAmount,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// is locked in controlled batch
	IsLockedInControlledBatch bool `json:"IsLockedInControlledBatch,omitempty"`

	// merchant Id
	MerchantID string `json:"MerchantId,omitempty"`

	// order Id or contribution Id
	OrderIDOrContributionID int32 `json:"OrderIdOrContributionId,omitempty"`

	// payment amount
	PaymentAmount float64 `json:"PaymentAmount,omitempty"`

	// payment date time
	// Format: date-time
	PaymentDateTime *strfmt.DateTime `json:"PaymentDateTime,omitempty"`

	// payment method
	PaymentMethod int32 `json:"PaymentMethod,omitempty"`

	// payment method description
	PaymentMethodDescription string `json:"PaymentMethodDescription,omitempty"`

	// processor reference Id
	ProcessorReferenceID string `json:"ProcessorReferenceId,omitempty"`
}

// Validate validates this payment available for refund
func (m *PaymentAvailableForRefund) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePaymentDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PaymentAvailableForRefund) validatePaymentDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("PaymentDateTime", "body", "date-time", m.PaymentDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this payment available for refund based on context it is used
func (m *PaymentAvailableForRefund) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PaymentAvailableForRefund) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PaymentAvailableForRefund) UnmarshalBinary(b []byte) error {
	var res PaymentAvailableForRefund
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
