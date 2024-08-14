// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// Seat seat
//
// swagger:model Seat
type Seat struct {

	// aisle indicator
	AisleIndicator string `json:"AisleIndicator,omitempty"`

	// allocation Id
	AllocationID int32 `json:"AllocationId,omitempty"`

	// display letter
	DisplayLetter string `json:"DisplayLetter,omitempty"`

	// has stairs
	HasStairs bool `json:"HasStairs,omitempty"`

	// hold code Id
	HoldCodeID int32 `json:"HoldCodeId,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// is seat
	IsSeat bool `json:"IsSeat,omitempty"`

	// logical seat number
	LogicalSeatNumber int32 `json:"LogicalSeatNumber,omitempty"`

	// logical seat row
	LogicalSeatRow int32 `json:"LogicalSeatRow,omitempty"`

	// screen Id
	ScreenID int32 `json:"ScreenId,omitempty"`

	// seat number
	SeatNumber string `json:"SeatNumber,omitempty"`

	// seat row
	SeatRow string `json:"SeatRow,omitempty"`

	// seat status Id
	SeatStatusID int32 `json:"SeatStatusId,omitempty"`

	// seat type Id
	SeatTypeID int32 `json:"SeatTypeId,omitempty"`

	// section Id
	SectionID int32 `json:"SectionId,omitempty"`

	// x position
	XPosition int32 `json:"XPosition,omitempty"`

	// y position
	YPosition int32 `json:"YPosition,omitempty"`

	// zone Id
	ZoneID int32 `json:"ZoneId,omitempty"`
}

// Validate validates this seat
func (m *Seat) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this seat based on context it is used
func (m *Seat) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *Seat) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Seat) UnmarshalBinary(b []byte) error {
	var res Seat
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}