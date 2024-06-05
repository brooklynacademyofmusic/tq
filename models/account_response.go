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

// AccountResponse account response
//
// swagger:model AccountResponse
type AccountResponse struct {

	// account number
	AccountNumber string `json:"AccountNumber,omitempty"`

	// account type
	AccountType *AccountTypeSummary `json:"AccountType,omitempty"`

	// bank identifier code
	BankIdentifierCode string `json:"BankIdentifierCode,omitempty"`

	// card expiry month
	CardExpiryMonth int32 `json:"CardExpiryMonth,omitempty"`

	// card expiry year
	CardExpiryYear int32 `json:"CardExpiryYear,omitempty"`

	// constituent Id
	ConstituentID int32 `json:"ConstituentId,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// direct debit account type
	DirectDebitAccountType *DirectDebitAccountTypeSummary `json:"DirectDebitAccountType,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// mandate number
	MandateNumber string `json:"MandateNumber,omitempty"`

	// mandate type
	MandateType int32 `json:"MandateType,omitempty"`

	// merchant Id
	MerchantID string `json:"MerchantId,omitempty"`

	// name
	Name string `json:"Name,omitempty"`

	// number first six
	NumberFirstSix string `json:"NumberFirstSix,omitempty"`

	// number last four
	NumberLastFour string `json:"NumberLastFour,omitempty"`

	// payment method group
	PaymentMethodGroup *PaymentMethodGroupSummary `json:"PaymentMethodGroup,omitempty"`

	// shopper reference
	ShopperReference string `json:"ShopperReference,omitempty"`

	// signature date
	// Format: date-time
	SignatureDate *strfmt.DateTime `json:"SignatureDate,omitempty"`

	// token
	Token string `json:"Token,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this account response
func (m *AccountResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDirectDebitAccountType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentMethodGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSignatureDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountResponse) validateAccountType(formats strfmt.Registry) error {
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

func (m *AccountResponse) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AccountResponse) validateDirectDebitAccountType(formats strfmt.Registry) error {
	if swag.IsZero(m.DirectDebitAccountType) { // not required
		return nil
	}

	if m.DirectDebitAccountType != nil {
		if err := m.DirectDebitAccountType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DirectDebitAccountType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DirectDebitAccountType")
			}
			return err
		}
	}

	return nil
}

func (m *AccountResponse) validatePaymentMethodGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentMethodGroup) { // not required
		return nil
	}

	if m.PaymentMethodGroup != nil {
		if err := m.PaymentMethodGroup.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PaymentMethodGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PaymentMethodGroup")
			}
			return err
		}
	}

	return nil
}

func (m *AccountResponse) validateSignatureDate(formats strfmt.Registry) error {
	if swag.IsZero(m.SignatureDate) { // not required
		return nil
	}

	if err := validate.FormatOf("SignatureDate", "body", "date-time", m.SignatureDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *AccountResponse) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this account response based on the context it is used
func (m *AccountResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDirectDebitAccountType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePaymentMethodGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *AccountResponse) contextValidateAccountType(ctx context.Context, formats strfmt.Registry) error {

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

func (m *AccountResponse) contextValidateDirectDebitAccountType(ctx context.Context, formats strfmt.Registry) error {

	if m.DirectDebitAccountType != nil {

		if swag.IsZero(m.DirectDebitAccountType) { // not required
			return nil
		}

		if err := m.DirectDebitAccountType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DirectDebitAccountType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DirectDebitAccountType")
			}
			return err
		}
	}

	return nil
}

func (m *AccountResponse) contextValidatePaymentMethodGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.PaymentMethodGroup != nil {

		if swag.IsZero(m.PaymentMethodGroup) { // not required
			return nil
		}

		if err := m.PaymentMethodGroup.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PaymentMethodGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PaymentMethodGroup")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *AccountResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *AccountResponse) UnmarshalBinary(b []byte) error {
	var res AccountResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
