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

// WebOrderSearchResponse web order search response
//
// swagger:model WebOrderSearchResponse
type WebOrderSearchResponse struct {

	// constituent Id
	ConstituentID int32 `json:"ConstituentId,omitempty"`

	// create date
	// Format: date-time
	CreateDate *strfmt.DateTime `json:"CreateDate,omitempty"`

	// is ok to print
	IsOkToPrint bool `json:"IsOkToPrint,omitempty"`

	// is rollover order
	IsRolloverOrder bool `json:"IsRolloverOrder,omitempty"`

	// locked by session key
	LockedBySessionKey string `json:"LockedBySessionKey,omitempty"`

	// locked in batch
	LockedInBatch int32 `json:"LockedInBatch,omitempty"`

	// mode of sale Id
	ModeOfSaleID int32 `json:"ModeOfSaleId,omitempty"`

	// number of unprinted seats
	NumberOfUnprintedSeats int32 `json:"NumberOfUnprintedSeats,omitempty"`

	// order date
	// Format: date-time
	OrderDate *strfmt.DateTime `json:"OrderDate,omitempty"`

	// order Id
	OrderID int32 `json:"OrderId,omitempty"`

	// total due amount
	TotalDueAmount float64 `json:"TotalDueAmount,omitempty"`

	// total paid amount
	TotalPaidAmount float64 `json:"TotalPaidAmount,omitempty"`
}

// Validate validates this web order search response
func (m *WebOrderSearchResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreateDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrderDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WebOrderSearchResponse) validateCreateDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CreateDate) { // not required
		return nil
	}

	if err := validate.FormatOf("CreateDate", "body", "date-time", m.CreateDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *WebOrderSearchResponse) validateOrderDate(formats strfmt.Registry) error {
	if swag.IsZero(m.OrderDate) { // not required
		return nil
	}

	if err := validate.FormatOf("OrderDate", "body", "date-time", m.OrderDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this web order search response based on context it is used
func (m *WebOrderSearchResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *WebOrderSearchResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WebOrderSearchResponse) UnmarshalBinary(b []byte) error {
	var res WebOrderSearchResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}