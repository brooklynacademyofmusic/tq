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

// ReceiptSetting receipt setting
//
// swagger:model ReceiptSetting
type ReceiptSetting struct {

	// control group
	ControlGroup *ControlGroupSummary `json:"ControlGroup,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// email footer
	EmailFooter string `json:"EmailFooter,omitempty"`

	// email header
	EmailHeader string `json:"EmailHeader,omitempty"`

	// email subject
	EmailSubject string `json:"EmailSubject,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// print footer
	PrintFooter string `json:"PrintFooter,omitempty"`

	// print header
	PrintHeader string `json:"PrintHeader,omitempty"`

	// receipt email profile
	ReceiptEmailProfile *EmailProfileSummary `json:"ReceiptEmailProfile,omitempty"`

	// ticket email profile
	TicketEmailProfile *EmailProfileSummary `json:"TicketEmailProfile,omitempty"`

	// ticket email subject
	TicketEmailSubject string `json:"TicketEmailSubject,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this receipt setting
func (m *ReceiptSetting) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateControlGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateReceiptEmailProfile(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTicketEmailProfile(formats); err != nil {
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

func (m *ReceiptSetting) validateControlGroup(formats strfmt.Registry) error {
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

func (m *ReceiptSetting) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ReceiptSetting) validateReceiptEmailProfile(formats strfmt.Registry) error {
	if swag.IsZero(m.ReceiptEmailProfile) { // not required
		return nil
	}

	if m.ReceiptEmailProfile != nil {
		if err := m.ReceiptEmailProfile.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ReceiptEmailProfile")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ReceiptEmailProfile")
			}
			return err
		}
	}

	return nil
}

func (m *ReceiptSetting) validateTicketEmailProfile(formats strfmt.Registry) error {
	if swag.IsZero(m.TicketEmailProfile) { // not required
		return nil
	}

	if m.TicketEmailProfile != nil {
		if err := m.TicketEmailProfile.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("TicketEmailProfile")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("TicketEmailProfile")
			}
			return err
		}
	}

	return nil
}

func (m *ReceiptSetting) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this receipt setting based on the context it is used
func (m *ReceiptSetting) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateControlGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateReceiptEmailProfile(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTicketEmailProfile(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ReceiptSetting) contextValidateControlGroup(ctx context.Context, formats strfmt.Registry) error {

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

func (m *ReceiptSetting) contextValidateReceiptEmailProfile(ctx context.Context, formats strfmt.Registry) error {

	if m.ReceiptEmailProfile != nil {

		if swag.IsZero(m.ReceiptEmailProfile) { // not required
			return nil
		}

		if err := m.ReceiptEmailProfile.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ReceiptEmailProfile")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ReceiptEmailProfile")
			}
			return err
		}
	}

	return nil
}

func (m *ReceiptSetting) contextValidateTicketEmailProfile(ctx context.Context, formats strfmt.Registry) error {

	if m.TicketEmailProfile != nil {

		if swag.IsZero(m.TicketEmailProfile) { // not required
			return nil
		}

		if err := m.TicketEmailProfile.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("TicketEmailProfile")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("TicketEmailProfile")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ReceiptSetting) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ReceiptSetting) UnmarshalBinary(b []byte) error {
	var res ReceiptSetting
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
