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

// BatchType batch type
//
// swagger:model BatchType
type BatchType struct {

	// batch type group
	BatchTypeGroup *BatchTypeGroupSummary `json:"BatchTypeGroup,omitempty"`

	// business unit
	BusinessUnit *BusinessUnitSummary `json:"BusinessUnit,omitempty"`

	// category
	Category int32 `json:"Category,omitempty"`

	// cntl indicator
	CntlIndicator bool `json:"CntlIndicator,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this batch type
func (m *BatchType) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateBatchTypeGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBusinessUnit(formats); err != nil {
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

func (m *BatchType) validateBatchTypeGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.BatchTypeGroup) { // not required
		return nil
	}

	if m.BatchTypeGroup != nil {
		if err := m.BatchTypeGroup.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BatchTypeGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BatchTypeGroup")
			}
			return err
		}
	}

	return nil
}

func (m *BatchType) validateBusinessUnit(formats strfmt.Registry) error {
	if swag.IsZero(m.BusinessUnit) { // not required
		return nil
	}

	if m.BusinessUnit != nil {
		if err := m.BusinessUnit.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BusinessUnit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BusinessUnit")
			}
			return err
		}
	}

	return nil
}

func (m *BatchType) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *BatchType) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this batch type based on the context it is used
func (m *BatchType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateBatchTypeGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBusinessUnit(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *BatchType) contextValidateBatchTypeGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.BatchTypeGroup != nil {

		if swag.IsZero(m.BatchTypeGroup) { // not required
			return nil
		}

		if err := m.BatchTypeGroup.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BatchTypeGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BatchTypeGroup")
			}
			return err
		}
	}

	return nil
}

func (m *BatchType) contextValidateBusinessUnit(ctx context.Context, formats strfmt.Registry) error {

	if m.BusinessUnit != nil {

		if swag.IsZero(m.BusinessUnit) { // not required
			return nil
		}

		if err := m.BusinessUnit.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BusinessUnit")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BusinessUnit")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *BatchType) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *BatchType) UnmarshalBinary(b []byte) error {
	var res BatchType
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
