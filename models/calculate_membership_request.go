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

// CalculateMembershipRequest calculate membership request
//
// swagger:model CalculateMembershipRequest
type CalculateMembershipRequest struct {

	// calc campaign Id
	CalcCampaignID int32 `json:"CalcCampaignId,omitempty"`

	// calc constituent Id
	CalcConstituentID int32 `json:"CalcConstituentId,omitempty"`

	// calc contribution amount
	CalcContributionAmount float64 `json:"CalcContributionAmount,omitempty"`

	// calc contribution date
	// Format: date-time
	CalcContributionDate *strfmt.DateTime `json:"CalcContributionDate,omitempty"`

	// calc expiration date
	// Format: date-time
	CalcExpirationDate *strfmt.DateTime `json:"CalcExpirationDate,omitempty"`

	// calc initial date
	// Format: date-time
	CalcInitialDate *strfmt.DateTime `json:"CalcInitialDate,omitempty"`

	// creditee Id
	CrediteeID int32 `json:"CrediteeId,omitempty"`

	// decline benefits
	DeclineBenefits string `json:"DeclineBenefits,omitempty"`

	// membership level override
	MembershipLevelOverride string `json:"MembershipLevelOverride,omitempty"`

	// membership organization Id
	MembershipOrganizationID int32 `json:"MembershipOrganizationId,omitempty"`

	// real or mirror
	RealOrMirror string `json:"RealOrMirror,omitempty"`

	// renew upgrade indicator
	RenewUpgradeIndicator string `json:"RenewUpgradeIndicator,omitempty"`
}

// Validate validates this calculate membership request
func (m *CalculateMembershipRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCalcContributionDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCalcExpirationDate(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCalcInitialDate(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CalculateMembershipRequest) validateCalcContributionDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CalcContributionDate) { // not required
		return nil
	}

	if err := validate.FormatOf("CalcContributionDate", "body", "date-time", m.CalcContributionDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *CalculateMembershipRequest) validateCalcExpirationDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CalcExpirationDate) { // not required
		return nil
	}

	if err := validate.FormatOf("CalcExpirationDate", "body", "date-time", m.CalcExpirationDate.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *CalculateMembershipRequest) validateCalcInitialDate(formats strfmt.Registry) error {
	if swag.IsZero(m.CalcInitialDate) { // not required
		return nil
	}

	if err := validate.FormatOf("CalcInitialDate", "body", "date-time", m.CalcInitialDate.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this calculate membership request based on context it is used
func (m *CalculateMembershipRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *CalculateMembershipRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CalculateMembershipRequest) UnmarshalBinary(b []byte) error {
	var res CalculateMembershipRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
