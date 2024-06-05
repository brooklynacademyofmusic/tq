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

// InventoryWebContent inventory web content
//
// swagger:model InventoryWebContent
type InventoryWebContent struct {

	// content type
	ContentType *WebContentTypeSummary `json:"ContentType,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// production element Id
	ProductionElementID int32 `json:"ProductionElementId,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`

	// value
	Value string `json:"Value,omitempty"`
}

// Validate validates this inventory web content
func (m *InventoryWebContent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateContentType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
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

func (m *InventoryWebContent) validateContentType(formats strfmt.Registry) error {
	if swag.IsZero(m.ContentType) { // not required
		return nil
	}

	if m.ContentType != nil {
		if err := m.ContentType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ContentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ContentType")
			}
			return err
		}
	}

	return nil
}

func (m *InventoryWebContent) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *InventoryWebContent) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this inventory web content based on the context it is used
func (m *InventoryWebContent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateContentType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *InventoryWebContent) contextValidateContentType(ctx context.Context, formats strfmt.Registry) error {

	if m.ContentType != nil {

		if swag.IsZero(m.ContentType) { // not required
			return nil
		}

		if err := m.ContentType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ContentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ContentType")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *InventoryWebContent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *InventoryWebContent) UnmarshalBinary(b []byte) error {
	var res InventoryWebContent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
