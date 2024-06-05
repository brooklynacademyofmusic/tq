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

// ProgramListing program listing
//
// swagger:model ProgramListing
type ProgramListing struct {

	// constituent
	Constituent *Entity `json:"Constituent,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// donation level
	DonationLevel *DonationLevelSummary `json:"DonationLevel,omitempty"`

	// edit indicator
	EditIndicator bool `json:"EditIndicator,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// program name
	ProgramName string `json:"ProgramName,omitempty"`

	// program type
	ProgramType *ProgramType `json:"ProgramType,omitempty"`

	// sort name
	SortName string `json:"SortName,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this program listing
func (m *ProgramListing) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConstituent(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDonationLevel(formats); err != nil {
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

func (m *ProgramListing) validateConstituent(formats strfmt.Registry) error {
	if swag.IsZero(m.Constituent) { // not required
		return nil
	}

	if m.Constituent != nil {
		if err := m.Constituent.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Constituent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Constituent")
			}
			return err
		}
	}

	return nil
}

func (m *ProgramListing) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ProgramListing) validateDonationLevel(formats strfmt.Registry) error {
	if swag.IsZero(m.DonationLevel) { // not required
		return nil
	}

	if m.DonationLevel != nil {
		if err := m.DonationLevel.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DonationLevel")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DonationLevel")
			}
			return err
		}
	}

	return nil
}

func (m *ProgramListing) validateProgramType(formats strfmt.Registry) error {
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

func (m *ProgramListing) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this program listing based on the context it is used
func (m *ProgramListing) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateConstituent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDonationLevel(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateProgramType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ProgramListing) contextValidateConstituent(ctx context.Context, formats strfmt.Registry) error {

	if m.Constituent != nil {

		if swag.IsZero(m.Constituent) { // not required
			return nil
		}

		if err := m.Constituent.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Constituent")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Constituent")
			}
			return err
		}
	}

	return nil
}

func (m *ProgramListing) contextValidateDonationLevel(ctx context.Context, formats strfmt.Registry) error {

	if m.DonationLevel != nil {

		if swag.IsZero(m.DonationLevel) { // not required
			return nil
		}

		if err := m.DonationLevel.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DonationLevel")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DonationLevel")
			}
			return err
		}
	}

	return nil
}

func (m *ProgramListing) contextValidateProgramType(ctx context.Context, formats strfmt.Registry) error {

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
func (m *ProgramListing) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ProgramListing) UnmarshalBinary(b []byte) error {
	var res ProgramListing
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
