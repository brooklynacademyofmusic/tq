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

// DonationLevel donation level
//
// swagger:model DonationLevel
type DonationLevel struct {

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// program type
	ProgramType *ProgramType `json:"ProgramType,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this donation level
func (m *DonationLevel) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProgramType(formats); err != nil {
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

func (m *DonationLevel) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *DonationLevel) validateProgramType(formats strfmt.Registry) error {
	if swag.IsZero(m.ProgramType) { // not required
		return nil
	}

	if m.ProgramType != nil {
		if err := m.ProgramType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ProgramType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ProgramType")
			}
			return err
		}
	}

	return nil
}

func (m *DonationLevel) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this donation level based on the context it is used
func (m *DonationLevel) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateProgramType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DonationLevel) contextValidateProgramType(ctx context.Context, formats strfmt.Registry) error {

	if m.ProgramType != nil {

		if swag.IsZero(m.ProgramType) { // not required
			return nil
		}

		if err := m.ProgramType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ProgramType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ProgramType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *DonationLevel) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DonationLevel) UnmarshalBinary(b []byte) error {
	var res DonationLevel
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
