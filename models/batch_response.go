// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// BatchResponse batch response
//
// swagger:model BatchResponse
type BatchResponse struct {

	// batch failed
	BatchFailed bool `json:"BatchFailed,omitempty"`

	// responses
	Responses []*Response `json:"Responses"`
}

// Validate validates this batch response
func (m *BatchResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateResponses(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BatchResponse) validateResponses(formats strfmt.Registry) error {
	if swag.IsZero(m.Responses) { // not required
		return nil
	}

	for i := 0; i < len(m.Responses); i++ {
		if swag.IsZero(m.Responses[i]) { // not required
			continue
		}

		if m.Responses[i] != nil {
			if err := m.Responses[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Responses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Responses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this batch response based on the context it is used
func (m *BatchResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateResponses(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BatchResponse) contextValidateResponses(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Responses); i++ {

		if m.Responses[i] != nil {

			if swag.IsZero(m.Responses[i]) { // not required
				return nil
			}

			if err := m.Responses[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Responses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Responses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *BatchResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BatchResponse) UnmarshalBinary(b []byte) error {
	var res BatchResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}