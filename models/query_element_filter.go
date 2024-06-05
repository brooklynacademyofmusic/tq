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

// QueryElementFilter query element filter
//
// swagger:model QueryElementFilter
type QueryElementFilter struct {

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// data type
	DataType int32 `json:"DataType,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// end of day
	EndOfDay bool `json:"EndOfDay,omitempty"`

	// filter element
	FilterElement string `json:"FilterElement,omitempty"`

	// group
	Group *QueryElementGroupSummary `json:"Group,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// reference description column
	ReferenceDescriptionColumn string `json:"ReferenceDescriptionColumn,omitempty"`

	// reference Id column
	ReferenceIDColumn string `json:"ReferenceIdColumn,omitempty"`

	// reference sort
	ReferenceSort string `json:"ReferenceSort,omitempty"`

	// reference table
	ReferenceTable string `json:"ReferenceTable,omitempty"`

	// reference where
	ReferenceWhere string `json:"ReferenceWhere,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this query element filter
func (m *QueryElementFilter) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateGroup(formats); err != nil {
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

func (m *QueryElementFilter) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *QueryElementFilter) validateGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.Group) { // not required
		return nil
	}

	if m.Group != nil {
		if err := m.Group.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Group")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Group")
			}
			return err
		}
	}

	return nil
}

func (m *QueryElementFilter) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this query element filter based on the context it is used
func (m *QueryElementFilter) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *QueryElementFilter) contextValidateGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.Group != nil {

		if swag.IsZero(m.Group) { // not required
			return nil
		}

		if err := m.Group.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Group")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Group")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *QueryElementFilter) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *QueryElementFilter) UnmarshalBinary(b []byte) error {
	var res QueryElementFilter
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
