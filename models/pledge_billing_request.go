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

// PledgeBillingRequest pledge billing request
//
// swagger:model PledgeBillingRequest
type PledgeBillingRequest struct {

	// acknowledgement letter Id
	AcknowledgementLetterID int32 `json:"AcknowledgementLetterId,omitempty"`

	// appeal Id
	AppealID int32 `json:"AppealId,omitempty"`

	// batch type Id
	BatchTypeID int32 `json:"BatchTypeId,omitempty"`

	// billing type Id
	BillingTypeID int32 `json:"BillingTypeId,omitempty"`

	// campaign Id
	CampaignID int32 `json:"CampaignId,omitempty"`

	// cutoff date time
	// Format: date-time
	CutoffDateTime strfmt.DateTime `json:"CutoffDateTime,omitempty"`

	// end date time
	// Format: date-time
	EndDateTime strfmt.DateTime `json:"EndDateTime,omitempty"`

	// fund ids
	FundIds string `json:"FundIds,omitempty"`

	// is label
	IsLabel bool `json:"IsLabel,omitempty"`

	// list Id
	ListID int32 `json:"ListId,omitempty"`

	// mail date time
	// Format: date-time
	MailDateTime strfmt.DateTime `json:"MailDateTime,omitempty"`

	// mail type Id
	MailTypeID int32 `json:"MailTypeId,omitempty"`

	// max number of bills to print
	MaxNumberOfBillsToPrint int32 `json:"MaxNumberOfBillsToPrint,omitempty"`

	// media type Id
	MediaTypeID int32 `json:"MediaTypeId,omitempty"`

	// min amount
	MinAmount float64 `json:"MinAmount,omitempty"`

	// min number of bills to print
	MinNumberOfBillsToPrint int32 `json:"MinNumberOfBillsToPrint,omitempty"`

	// new source description
	NewSourceDescription string `json:"NewSourceDescription,omitempty"`

	// payment method group Id
	PaymentMethodGroupID int32 `json:"PaymentMethodGroupId,omitempty"`

	// salutation type Id
	SalutationTypeID int32 `json:"SalutationTypeId,omitempty"`

	// should update
	ShouldUpdate bool `json:"ShouldUpdate,omitempty"`

	// start date time
	// Format: date-time
	StartDateTime strfmt.DateTime `json:"StartDateTime,omitempty"`

	// user Id
	UserID string `json:"UserId,omitempty"`
}

// Validate validates this pledge billing request
func (m *PledgeBillingRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCutoffDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEndDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateMailDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateStartDateTime(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PledgeBillingRequest) validateCutoffDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CutoffDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CutoffDateTime", "body", "date-time", m.CutoffDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PledgeBillingRequest) validateEndDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.EndDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("EndDateTime", "body", "date-time", m.EndDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PledgeBillingRequest) validateMailDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.MailDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("MailDateTime", "body", "date-time", m.MailDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *PledgeBillingRequest) validateStartDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.StartDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("StartDateTime", "body", "date-time", m.StartDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this pledge billing request based on context it is used
func (m *PledgeBillingRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *PledgeBillingRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PledgeBillingRequest) UnmarshalBinary(b []byte) error {
	var res PledgeBillingRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}