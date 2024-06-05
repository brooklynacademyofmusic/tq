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

// PaymentMethod payment method
//
// swagger:model PaymentMethod
type PaymentMethod struct {

	// account type
	AccountType *AccountTypeSummary `json:"AccountType,omitempty"`

	// auth indicator
	AuthIndicator bool `json:"AuthIndicator,omitempty"`

	// business unit Id
	BusinessUnitID int32 `json:"BusinessUnitId,omitempty"`

	// can refund
	CanRefund bool `json:"CanRefund,omitempty"`

	// control group
	ControlGroup *ControlGroupSummary `json:"ControlGroup,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// currency type Id
	CurrencyTypeID int32 `json:"CurrencyTypeId,omitempty"`

	// default indicator
	DefaultIndicator bool `json:"DefaultIndicator,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// gift aid indicator
	GiftAidIndicator bool `json:"GiftAidIndicator,omitempty"`

	// gl account Id
	GlAccountID string `json:"GlAccountId,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// income
	Income bool `json:"Income,omitempty"`

	// merchant Id
	MerchantID string `json:"MerchantId,omitempty"`

	// merchant Id for swipe
	MerchantIDForSwipe string `json:"MerchantIdForSwipe,omitempty"`

	// no copies on auth
	NoCopiesOnAuth int32 `json:"NoCopiesOnAuth,omitempty"`

	// no copies on save
	NoCopiesOnSave int32 `json:"NoCopiesOnSave,omitempty"`

	// open cash drawer
	OpenCashDrawer bool `json:"OpenCashDrawer,omitempty"`

	// payment method group
	PaymentMethodGroup *PaymentMethodGroupSummary `json:"PaymentMethodGroup,omitempty"`

	// payment type
	PaymentType *PaymentTypeSummary `json:"PaymentType,omitempty"`

	// receipt format Id
	ReceiptFormatID int32 `json:"ReceiptFormatId,omitempty"`

	// require check indicator
	RequireCheckIndicator bool `json:"RequireCheckIndicator,omitempty"`

	// require cvv
	RequireCvv bool `json:"RequireCvv,omitempty"`

	// require postal code
	RequirePostalCode string `json:"RequirePostalCode,omitempty"`

	// short desc
	ShortDesc string `json:"ShortDesc,omitempty"`

	// store tendered amount
	StoreTenderedAmount bool `json:"StoreTenderedAmount,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`

	// use with card reader
	UseWithCardReader bool `json:"UseWithCardReader,omitempty"`
}

// Validate validates this payment method
func (m *PaymentMethod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateControlGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentMethodGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentType(formats); err != nil {
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

func (m *PaymentMethod) validateAccountType(formats strfmt.Registry) error {
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

func (m *PaymentMethod) validateControlGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.ControlGroup) { // not required
		return nil
	}

	if m.ControlGroup != nil {
		if err := m.ControlGroup.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ControlGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ControlGroup")
			}
			return err
		}
	}

	return nil
}

func (m *PaymentMethod) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PaymentMethod) validatePaymentMethodGroup(formats strfmt.Registry) error {
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

func (m *PaymentMethod) validatePaymentType(formats strfmt.Registry) error {
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

func (m *PaymentMethod) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this payment method based on the context it is used
func (m *PaymentMethod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateControlGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePaymentMethodGroup(ctx, formats); err != nil {
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

func (m *PaymentMethod) contextValidateAccountType(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PaymentMethod) contextValidateControlGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.ControlGroup != nil {

		if swag.IsZero(m.ControlGroup) { // not required
			return nil
		}

		if err := m.ControlGroup.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ControlGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ControlGroup")
			}
			return err
		}
	}

	return nil
}

func (m *PaymentMethod) contextValidatePaymentMethodGroup(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PaymentMethod) contextValidatePaymentType(ctx context.Context, formats strfmt.Registry) error {

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
func (m *PaymentMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PaymentMethod) UnmarshalBinary(b []byte) error {
	var res PaymentMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
