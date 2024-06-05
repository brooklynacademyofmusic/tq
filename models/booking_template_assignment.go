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

// BookingTemplateAssignment booking template assignment
//
// swagger:model BookingTemplateAssignment
type BookingTemplateAssignment struct {

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// edit indicator
	EditIndicator bool `json:"EditIndicator,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// minutes duration
	MinutesDuration int32 `json:"MinutesDuration,omitempty"`

	// minutes offset
	MinutesOffset int32 `json:"MinutesOffset,omitempty"`

	// override count
	OverrideCount int32 `json:"OverrideCount,omitempty"`

	// qualifications
	Qualifications []int32 `json:"Qualifications"`

	// resource type
	ResourceType *ResourceTypeSummary `json:"ResourceType,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`

	// view indicator
	ViewIndicator bool `json:"ViewIndicator,omitempty"`
}

// Validate validates this booking template assignment
func (m *BookingTemplateAssignment) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateResourceType(formats); err != nil {
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

func (m *BookingTemplateAssignment) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *BookingTemplateAssignment) validateResourceType(formats strfmt.Registry) error {
	if swag.IsZero(m.ResourceType) { // not required
		return nil
	}

	if m.ResourceType != nil {
		if err := m.ResourceType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ResourceType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ResourceType")
			}
			return err
		}
	}

	return nil
}

func (m *BookingTemplateAssignment) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this booking template assignment based on the context it is used
func (m *BookingTemplateAssignment) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateResourceType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BookingTemplateAssignment) contextValidateResourceType(ctx context.Context, formats strfmt.Registry) error {

	if m.ResourceType != nil {

		if swag.IsZero(m.ResourceType) { // not required
			return nil
		}

		if err := m.ResourceType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ResourceType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ResourceType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *BookingTemplateAssignment) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BookingTemplateAssignment) UnmarshalBinary(b []byte) error {
	var res BookingTemplateAssignment
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
