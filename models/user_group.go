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

// UserGroup user group
//
// swagger:model UserGroup
type UserGroup struct {

	// allow analytics
	AllowAnalytics bool `json:"AllowAnalytics,omitempty"`

	// allow app
	AllowApp bool `json:"AllowApp,omitempty"`

	// allow on the go
	AllowOnTheGo bool `json:"AllowOnTheGo,omitempty"`

	// allow tablet
	AllowTablet bool `json:"AllowTablet,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// division
	Division *Division `json:"Division,omitempty"`

	// Id
	ID string `json:"Id,omitempty"`

	// is admin
	IsAdmin bool `json:"IsAdmin,omitempty"`

	// name
	Name string `json:"Name,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this user group
func (m *UserGroup) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDivision(formats); err != nil {
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

func (m *UserGroup) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *UserGroup) validateDivision(formats strfmt.Registry) error {
	if swag.IsZero(m.Division) { // not required
		return nil
	}

	if m.Division != nil {
		if err := m.Division.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Division")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Division")
			}
			return err
		}
	}

	return nil
}

func (m *UserGroup) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this user group based on the context it is used
func (m *UserGroup) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDivision(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserGroup) contextValidateDivision(ctx context.Context, formats strfmt.Registry) error {

	if m.Division != nil {

		if swag.IsZero(m.Division) { // not required
			return nil
		}

		if err := m.Division.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Division")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Division")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserGroup) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserGroup) UnmarshalBinary(b []byte) error {
	var res UserGroup
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}