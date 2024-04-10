// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// LineItemPerformance line item performance
//
// swagger:model LineItemPerformance
type LineItemPerformance struct {

	// Id
	ID int32 `json:"Id,omitempty"`

	// production season Id
	ProductionSeasonID int32 `json:"ProductionSeasonId,omitempty"`

	// season Id
	SeasonID int32 `json:"SeasonId,omitempty"`
}

// Validate validates this line item performance
func (m *LineItemPerformance) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this line item performance based on context it is used
func (m *LineItemPerformance) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *LineItemPerformance) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *LineItemPerformance) UnmarshalBinary(b []byte) error {
	var res LineItemPerformance
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}