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

// ModeOfSaleSurveyQuestion mode of sale survey question
//
// swagger:model ModeOfSaleSurveyQuestion
type ModeOfSaleSurveyQuestion struct {

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// mode of sale
	ModeOfSale *ModeOfSaleSummary `json:"ModeOfSale,omitempty"`

	// question
	Question *SurveyQuestion `json:"Question,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`
}

// Validate validates this mode of sale survey question
func (m *ModeOfSaleSurveyQuestion) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateModeOfSale(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateQuestion(formats); err != nil {
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

func (m *ModeOfSaleSurveyQuestion) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ModeOfSaleSurveyQuestion) validateModeOfSale(formats strfmt.Registry) error {
	if swag.IsZero(m.ModeOfSale) { // not required
		return nil
	}

	if m.ModeOfSale != nil {
		if err := m.ModeOfSale.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ModeOfSale")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ModeOfSale")
			}
			return err
		}
	}

	return nil
}

func (m *ModeOfSaleSurveyQuestion) validateQuestion(formats strfmt.Registry) error {
	if swag.IsZero(m.Question) { // not required
		return nil
	}

	if m.Question != nil {
		if err := m.Question.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Question")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Question")
			}
			return err
		}
	}

	return nil
}

func (m *ModeOfSaleSurveyQuestion) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this mode of sale survey question based on the context it is used
func (m *ModeOfSaleSurveyQuestion) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateModeOfSale(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateQuestion(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ModeOfSaleSurveyQuestion) contextValidateModeOfSale(ctx context.Context, formats strfmt.Registry) error {

	if m.ModeOfSale != nil {

		if swag.IsZero(m.ModeOfSale) { // not required
			return nil
		}

		if err := m.ModeOfSale.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("ModeOfSale")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("ModeOfSale")
			}
			return err
		}
	}

	return nil
}

func (m *ModeOfSaleSurveyQuestion) contextValidateQuestion(ctx context.Context, formats strfmt.Registry) error {

	if m.Question != nil {

		if swag.IsZero(m.Question) { // not required
			return nil
		}

		if err := m.Question.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Question")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Question")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *ModeOfSaleSurveyQuestion) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ModeOfSaleSurveyQuestion) UnmarshalBinary(b []byte) error {
	var res ModeOfSaleSurveyQuestion
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
