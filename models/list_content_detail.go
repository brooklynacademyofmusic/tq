// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// ListContentDetail list content detail
//
// swagger:model ListContentDetail
type ListContentDetail struct {

	// constituent
	Constituent *ConstituentDisplaySummary `json:"Constituent,omitempty"`
}

// Validate validates this list content detail
func (m *ListContentDetail) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateConstituent(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ListContentDetail) validateConstituent(formats strfmt.Registry) error {
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

// ContextValidate validate this list content detail based on the context it is used
func (m *ListContentDetail) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateConstituent(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ListContentDetail) contextValidateConstituent(ctx context.Context, formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *ListContentDetail) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ListContentDetail) UnmarshalBinary(b []byte) error {
	var res ListContentDetail
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}