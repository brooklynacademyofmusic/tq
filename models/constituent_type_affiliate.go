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

// ConstituentTypeAffiliate constituent type affiliate
//
// swagger:model ConstituentTypeAffiliate
type ConstituentTypeAffiliate struct {

	// affiliation type
	AffiliationType *AffiliationTypeSummary `json:"AffiliationType,omitempty"`

	// constituent type
	ConstituentType *ConstituentTypeSummary `json:"ConstituentType,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// household primary
	HouseholdPrimary bool `json:"HouseholdPrimary,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// rank
	Rank int32 `json:"Rank,omitempty"`

	// show with group
	ShowWithGroup bool `json:"ShowWithGroup,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this constituent type affiliate
func (m *ConstituentTypeAffiliate) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAffiliationType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateConstituentType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
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

func (m *ConstituentTypeAffiliate) validateAffiliationType(formats strfmt.Registry) error {
	if swag.IsZero(m.AffiliationType) { // not required
		return nil
	}

	if m.AffiliationType != nil {
		if err := m.AffiliationType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AffiliationType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AffiliationType")
			}
			return err
		}
	}

	return nil
}

func (m *ConstituentTypeAffiliate) validateConstituentType(formats strfmt.Registry) error {
	if swag.IsZero(m.ConstituentType) { // not required
		return nil
	}

	if m.ConstituentType != nil {
		if err := m.ConstituentType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ConstituentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ConstituentType")
			}
			return err
		}
	}

	return nil
}

func (m *ConstituentTypeAffiliate) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ConstituentTypeAffiliate) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this constituent type affiliate based on the context it is used
func (m *ConstituentTypeAffiliate) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAffiliationType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateConstituentType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ConstituentTypeAffiliate) contextValidateAffiliationType(ctx context.Context, formats strfmt.Registry) error {

	if m.AffiliationType != nil {

		if swag.IsZero(m.AffiliationType) { // not required
			return nil
		}

		if err := m.AffiliationType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AffiliationType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AffiliationType")
			}
			return err
		}
	}

	return nil
}

func (m *ConstituentTypeAffiliate) contextValidateConstituentType(ctx context.Context, formats strfmt.Registry) error {

	if m.ConstituentType != nil {

		if swag.IsZero(m.ConstituentType) { // not required
			return nil
		}

		if err := m.ConstituentType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ConstituentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ConstituentType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ConstituentTypeAffiliate) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ConstituentTypeAffiliate) UnmarshalBinary(b []byte) error {
	var res ConstituentTypeAffiliate
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}