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

// PriceType price type
//
// swagger:model PriceType
type PriceType struct {

	// alias description
	AliasDescription string `json:"AliasDescription,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// default ticket design
	DefaultTicketDesign *TicketDesign `json:"DefaultTicketDesign,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// edit indicator
	EditIndicator bool `json:"EditIndicator,omitempty"`

	// editable indicator
	EditableIndicator bool `json:"EditableIndicator,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// price type category
	PriceTypeCategory *PriceTypeCategorySummary `json:"PriceTypeCategory,omitempty"`

	// price type group
	PriceTypeGroup *PriceTypeGroupSummary `json:"PriceTypeGroup,omitempty"`

	// reason indicator
	ReasonIndicator bool `json:"ReasonIndicator,omitempty"`

	// short description
	ShortDescription string `json:"ShortDescription,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this price type
func (m *PriceType) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultTicketDesign(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePriceTypeCategory(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePriceTypeGroup(formats); err != nil {
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

func (m *PriceType) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PriceType) validateDefaultTicketDesign(formats strfmt.Registry) error {
	if swag.IsZero(m.DefaultTicketDesign) { // not required
		return nil
	}

	if m.DefaultTicketDesign != nil {
		if err := m.DefaultTicketDesign.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultTicketDesign")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultTicketDesign")
			}
			return err
		}
	}

	return nil
}

func (m *PriceType) validatePriceTypeCategory(formats strfmt.Registry) error {
	if swag.IsZero(m.PriceTypeCategory) { // not required
		return nil
	}

	if m.PriceTypeCategory != nil {
		if err := m.PriceTypeCategory.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PriceTypeCategory")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PriceTypeCategory")
			}
			return err
		}
	}

	return nil
}

func (m *PriceType) validatePriceTypeGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.PriceTypeGroup) { // not required
		return nil
	}

	if m.PriceTypeGroup != nil {
		if err := m.PriceTypeGroup.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PriceTypeGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PriceTypeGroup")
			}
			return err
		}
	}

	return nil
}

func (m *PriceType) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this price type based on the context it is used
func (m *PriceType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDefaultTicketDesign(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePriceTypeCategory(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePriceTypeGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PriceType) contextValidateDefaultTicketDesign(ctx context.Context, formats strfmt.Registry) error {

	if m.DefaultTicketDesign != nil {

		if swag.IsZero(m.DefaultTicketDesign) { // not required
			return nil
		}

		if err := m.DefaultTicketDesign.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultTicketDesign")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultTicketDesign")
			}
			return err
		}
	}

	return nil
}

func (m *PriceType) contextValidatePriceTypeCategory(ctx context.Context, formats strfmt.Registry) error {

	if m.PriceTypeCategory != nil {

		if swag.IsZero(m.PriceTypeCategory) { // not required
			return nil
		}

		if err := m.PriceTypeCategory.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PriceTypeCategory")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PriceTypeCategory")
			}
			return err
		}
	}

	return nil
}

func (m *PriceType) contextValidatePriceTypeGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.PriceTypeGroup != nil {

		if swag.IsZero(m.PriceTypeGroup) { // not required
			return nil
		}

		if err := m.PriceTypeGroup.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PriceTypeGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PriceTypeGroup")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PriceType) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PriceType) UnmarshalBinary(b []byte) error {
	var res PriceType
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
