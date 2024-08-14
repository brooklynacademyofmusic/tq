// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// SeatSummary seat summary
//
// swagger:model SeatSummary
type SeatSummary struct {

	// available count
	AvailableCount int32 `json:"AvailableCount,omitempty"`

	// screen Id
	ScreenID int32 `json:"ScreenId,omitempty"`

	// section Id
	SectionID int32 `json:"SectionId,omitempty"`

	// zone Id
	ZoneID int32 `json:"ZoneId,omitempty"`
}

// Validate validates this seat summary
func (m *SeatSummary) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this seat summary based on context it is used
func (m *SeatSummary) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SeatSummary) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SeatSummary) UnmarshalBinary(b []byte) error {
	var res SeatSummary
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}