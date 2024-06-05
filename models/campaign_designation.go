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

// CampaignDesignation campaign designation
//
// swagger:model CampaignDesignation
type CampaignDesignation struct {

	// campaign
	Campaign *CampaignSummary `json:"Campaign,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// default indicator
	DefaultIndicator bool `json:"DefaultIndicator,omitempty"`

	// designation
	Designation *ContributionDesignationSummary `json:"Designation,omitempty"`

	// edit indicator
	EditIndicator bool `json:"EditIndicator,omitempty"`

	// goal amount
	GoalAmount float64 `json:"GoalAmount,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this campaign designation
func (m *CampaignDesignation) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCampaign(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDesignation(formats); err != nil {
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

func (m *CampaignDesignation) validateCampaign(formats strfmt.Registry) error {
	if swag.IsZero(m.Campaign) { // not required
		return nil
	}

	if m.Campaign != nil {
		if err := m.Campaign.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Campaign")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Campaign")
			}
			return err
		}
	}

	return nil
}

func (m *CampaignDesignation) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *CampaignDesignation) validateDesignation(formats strfmt.Registry) error {
	if swag.IsZero(m.Designation) { // not required
		return nil
	}

	if m.Designation != nil {
		if err := m.Designation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Designation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Designation")
			}
			return err
		}
	}

	return nil
}

func (m *CampaignDesignation) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this campaign designation based on the context it is used
func (m *CampaignDesignation) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCampaign(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDesignation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CampaignDesignation) contextValidateCampaign(ctx context.Context, formats strfmt.Registry) error {

	if m.Campaign != nil {

		if swag.IsZero(m.Campaign) { // not required
			return nil
		}

		if err := m.Campaign.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Campaign")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Campaign")
			}
			return err
		}
	}

	return nil
}

func (m *CampaignDesignation) contextValidateDesignation(ctx context.Context, formats strfmt.Registry) error {

	if m.Designation != nil {

		if swag.IsZero(m.Designation) { // not required
			return nil
		}

		if err := m.Designation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Designation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Designation")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CampaignDesignation) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CampaignDesignation) UnmarshalBinary(b []byte) error {
	var res CampaignDesignation
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
