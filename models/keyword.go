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

// Keyword keyword
//
// swagger:model Keyword
type Keyword struct {

	// category
	Category *KeywordCategorySummary `json:"Category,omitempty"`

	// constituent type
	ConstituentType int32 `json:"ConstituentType,omitempty"`

	// control group
	ControlGroup *ControlGroupSummary `json:"ControlGroup,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// custom default value
	CustomDefaultValue string `json:"CustomDefaultValue,omitempty"`

	// custom Id
	CustomID int32 `json:"CustomId,omitempty"`

	// custom limit
	CustomLimit int32 `json:"CustomLimit,omitempty"`

	// custom required
	CustomRequired bool `json:"CustomRequired,omitempty"`

	// data type
	DataType string `json:"DataType,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// detail column
	DetailColumn string `json:"DetailColumn,omitempty"`

	// detail table
	DetailTable string `json:"DetailTable,omitempty"`

	// edit indicator
	EditIndicator bool `json:"EditIndicator,omitempty"`

	// edit mask
	EditMask string `json:"EditMask,omitempty"`

	// extended description
	ExtendedDescription string `json:"ExtendedDescription,omitempty"`

	// frequent update date
	// Format: date-time
	FrequentUpdateDate strfmt.DateTime `json:"FrequentUpdateDate,omitempty"`

	// help text
	HelpText string `json:"HelpText,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// key column
	KeyColumn string `json:"KeyColumn,omitempty"`

	// keyword use
	KeywordUse string `json:"KeywordUse,omitempty"`

	// multiple value
	MultipleValue bool `json:"MultipleValue,omitempty"`

	// parent key column
	ParentKeyColumn string `json:"ParentKeyColumn,omitempty"`

	// parent table
	ParentTable string `json:"ParentTable,omitempty"`

	// primary group default
	PrimaryGroupDefault string `json:"PrimaryGroupDefault,omitempty"`

	// reference description column
	ReferenceDescriptionColumn string `json:"ReferenceDescriptionColumn,omitempty"`

	// reference Id column
	ReferenceIDColumn string `json:"ReferenceIdColumn,omitempty"`

	// reference sort
	ReferenceSort string `json:"ReferenceSort,omitempty"`

	// reference table
	ReferenceTable string `json:"ReferenceTable,omitempty"`

	// reference where
	ReferenceWhere string `json:"ReferenceWhere,omitempty"`

	// sort order
	SortOrder int32 `json:"SortOrder,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime strfmt.DateTime `json:"UpdatedDateTime,omitempty"`

	// use for search
	UseForSearch bool `json:"UseForSearch,omitempty"`

	// values coded indicator
	ValuesCodedIndicator bool `json:"ValuesCodedIndicator,omitempty"`
}

// Validate validates this keyword
func (m *Keyword) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCategory(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateControlGroup(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFrequentUpdateDate(formats); err != nil {
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

func (m *Keyword) validateCategory(formats strfmt.Registry) error {
	if swag.IsZero(m.Category) { // not required
		return nil
	}

	if m.Category != nil {
		if err := m.Category.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Category")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Category")
			}
			return err
		}
	}

	return nil
}

func (m *Keyword) validateControlGroup(formats strfmt.Registry) error {
	if swag.IsZero(m.ControlGroup) { // not required
		return nil
	}

	if m.ControlGroup != nil {
		if err := m.ControlGroup.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ControlGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ControlGroup")
			}
			return err
		}
	}

	return nil
}

func (m *Keyword) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Keyword) validateFrequentUpdateDate(formats strfmt.Registry) error {
	if swag.IsZero(m.FrequentUpdateDate) { // not required
		return nil
	}

	if err := validate.FormatOf("FrequentUpdateDate", "body", "date-time", m.FrequentUpdateDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *Keyword) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this keyword based on the context it is used
func (m *Keyword) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateCategory(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateControlGroup(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *Keyword) contextValidateCategory(ctx context.Context, formats strfmt.Registry) error {

	if m.Category != nil {

		if swag.IsZero(m.Category) { // not required
			return nil
		}

		if err := m.Category.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Category")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Category")
			}
			return err
		}
	}

	return nil
}

func (m *Keyword) contextValidateControlGroup(ctx context.Context, formats strfmt.Registry) error {

	if m.ControlGroup != nil {

		if swag.IsZero(m.ControlGroup) { // not required
			return nil
		}

		if err := m.ControlGroup.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ControlGroup")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ControlGroup")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Keyword) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Keyword) UnmarshalBinary(b []byte) error {
	var res Keyword
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}