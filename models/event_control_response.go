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
	"github.com/go-openapi/validate"
)

// EventControlResponse event control response
//
// swagger:model EventControlResponse
type EventControlResponse struct {

	// end date
	// Format: date-time
	EndDate *strfmt.DateTime `json:"EndDate,omitempty"`

	// event control set
	EventControlSet []*EventControl `json:"EventControlSet"`

	// start date
	// Format: date-time
	StartDate *strfmt.DateTime `json:"StartDate,omitempty"`
}

// Validate validates this event control response
func (m *EventControlResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEndDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEventControlSet(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EventControlResponse) validateEndDate(formats strfmt.Registry) error {
	if swag.IsZero(m.EndDate) { // not required
		return nil
	}

	if err := validate.FormatOf("EndDate", "body", "date-time", m.EndDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *EventControlResponse) validateEventControlSet(formats strfmt.Registry) error {
	if swag.IsZero(m.EventControlSet) { // not required
		return nil
	}

	for i := 0; i < len(m.EventControlSet); i++ {
		if swag.IsZero(m.EventControlSet[i]) { // not required
			continue
		}

		if m.EventControlSet[i] != nil {
			if err := m.EventControlSet[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("EventControlSet" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("EventControlSet" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *EventControlResponse) validateStartDate(formats strfmt.Registry) error {
	if swag.IsZero(m.StartDate) { // not required
		return nil
	}

	if err := validate.FormatOf("StartDate", "body", "date-time", m.StartDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this event control response based on the context it is used
func (m *EventControlResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEventControlSet(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EventControlResponse) contextValidateEventControlSet(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.EventControlSet); i++ {

		if m.EventControlSet[i] != nil {

			if swag.IsZero(m.EventControlSet[i]) { // not required
				return nil
			}

			if err := m.EventControlSet[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("EventControlSet" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("EventControlSet" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *EventControlResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EventControlResponse) UnmarshalBinary(b []byte) error {
	var res EventControlResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
