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

// TicketHeader ticket header
//
// swagger:model TicketHeader
type TicketHeader struct {

	// ticket elements
	TicketElements []*TicketElement `json:"TicketElements"`
}

// Validate validates this ticket header
func (m *TicketHeader) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateTicketElements(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TicketHeader) validateTicketElements(formats strfmt.Registry) error {
	if swag.IsZero(m.TicketElements) { // not required
		return nil
	}

	for i := 0; i < len(m.TicketElements); i++ {
		if swag.IsZero(m.TicketElements[i]) { // not required
			continue
		}

		if m.TicketElements[i] != nil {
			if err := m.TicketElements[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("TicketElements" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("TicketElements" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this ticket header based on the context it is used
func (m *TicketHeader) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateTicketElements(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *TicketHeader) contextValidateTicketElements(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.TicketElements); i++ {

		if m.TicketElements[i] != nil {

			if swag.IsZero(m.TicketElements[i]) { // not required
				return nil
			}

			if err := m.TicketElements[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("TicketElements" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("TicketElements" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *TicketHeader) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *TicketHeader) UnmarshalBinary(b []byte) error {
	var res TicketHeader
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}