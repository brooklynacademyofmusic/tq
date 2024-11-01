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

// PlanWorker plan worker
//
// swagger:model PlanWorker
type PlanWorker struct {

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// edit indicator
	EditIndicator bool `json:"EditIndicator,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// plan
	Plan *Entity `json:"Plan,omitempty"`

	// primary indicator
	PrimaryIndicator bool `json:"PrimaryIndicator,omitempty"`

	// role
	Role *WorkerRoleSummary `json:"Role,omitempty"`

	// show in portfolio
	ShowInPortfolio bool `json:"ShowInPortfolio,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`

	// worker
	Worker *ConstituentDisplaySummary `json:"Worker,omitempty"`
}

// Validate validates this plan worker
func (m *PlanWorker) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePlan(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRole(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWorker(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PlanWorker) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PlanWorker) validatePlan(formats strfmt.Registry) error {
	if swag.IsZero(m.Plan) { // not required
		return nil
	}

	if m.Plan != nil {
		if err := m.Plan.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Plan")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Plan")
			}
			return err
		}
	}

	return nil
}

func (m *PlanWorker) validateRole(formats strfmt.Registry) error {
	if swag.IsZero(m.Role) { // not required
		return nil
	}

	if m.Role != nil {
		if err := m.Role.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Role")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Role")
			}
			return err
		}
	}

	return nil
}

func (m *PlanWorker) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PlanWorker) validateWorker(formats strfmt.Registry) error {
	if swag.IsZero(m.Worker) { // not required
		return nil
	}

	if m.Worker != nil {
		if err := m.Worker.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Worker")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Worker")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this plan worker based on the context it is used
func (m *PlanWorker) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePlan(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRole(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWorker(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PlanWorker) contextValidatePlan(ctx context.Context, formats strfmt.Registry) error {

	if m.Plan != nil {

		if swag.IsZero(m.Plan) { // not required
			return nil
		}

		if err := m.Plan.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Plan")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Plan")
			}
			return err
		}
	}

	return nil
}

func (m *PlanWorker) contextValidateRole(ctx context.Context, formats strfmt.Registry) error {

	if m.Role != nil {

		if swag.IsZero(m.Role) { // not required
			return nil
		}

		if err := m.Role.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Role")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Role")
			}
			return err
		}
	}

	return nil
}

func (m *PlanWorker) contextValidateWorker(ctx context.Context, formats strfmt.Registry) error {

	if m.Worker != nil {

		if swag.IsZero(m.Worker) { // not required
			return nil
		}

		if err := m.Worker.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Worker")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Worker")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PlanWorker) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PlanWorker) UnmarshalBinary(b []byte) error {
	var res PlanWorker
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}