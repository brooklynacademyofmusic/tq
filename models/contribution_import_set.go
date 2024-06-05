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

// ContributionImportSet contribution import set
//
// swagger:model ContributionImportSet
type ContributionImportSet struct {

	// account match keyword
	AccountMatchKeyword *KeywordSummary `json:"AccountMatchKeyword,omitempty"`

	// acknowledgment letter mode
	AcknowledgmentLetterMode int32 `json:"AcknowledgmentLetterMode,omitempty"`

	// batch type
	BatchType *BatchTypeSummary `json:"BatchType,omitempty"`

	// billing schedule
	BillingSchedule *BillingScheduleSummary `json:"BillingSchedule,omitempty"`

	// billing type
	BillingType *BillingTypeSummary `json:"BillingType,omitempty"`

	// campaign
	Campaign *CampaignSummary `json:"Campaign,omitempty"`

	// contribution date time
	// Format: date-time
	ContributionDateTime *strfmt.DateTime `json:"ContributionDateTime,omitempty"`

	// contribution pay mode
	ContributionPayMode int32 `json:"ContributionPayMode,omitempty"`

	// create location
	CreateLocation string `json:"CreateLocation,omitempty"`

	// create potential duplicate
	CreatePotentialDuplicate bool `json:"CreatePotentialDuplicate,omitempty"`

	// created by
	CreatedBy string `json:"CreatedBy,omitempty"`

	// created date time
	// Format: date-time
	CreatedDateTime *strfmt.DateTime `json:"CreatedDateTime,omitempty"`

	// creditee mode
	CrediteeMode int32 `json:"CrediteeMode,omitempty"`

	// creditee type
	CrediteeType *CrediteeTypeSummary `json:"CrediteeType,omitempty"`

	// default constituent type
	DefaultConstituentType *ConstituentTypeSummary `json:"DefaultConstituentType,omitempty"`

	// default country code
	DefaultCountryCode string `json:"DefaultCountryCode,omitempty"`

	// default household constituent type
	DefaultHouseholdConstituentType *ConstituentTypeSummary `json:"DefaultHouseholdConstituentType,omitempty"`

	// default original source
	DefaultOriginalSource *OriginalSourceSummary `json:"DefaultOriginalSource,omitempty"`

	// description
	Description string `json:"Description,omitempty"`

	// designation
	Designation *ContributionDesignationSummary `json:"Designation,omitempty"`

	// file path
	FilePath string `json:"FilePath,omitempty"`

	// format file
	FormatFile string `json:"FormatFile,omitempty"`

	// fund
	Fund *FundSummary `json:"Fund,omitempty"`

	// Id
	ID int32 `json:"Id,omitempty"`

	// import ref no location
	ImportRefNoLocation int32 `json:"ImportRefNoLocation,omitempty"`

	// inactive
	Inactive bool `json:"Inactive,omitempty"`

	// payment method
	PaymentMethod *PaymentMethodSummary `json:"PaymentMethod,omitempty"`

	// sales channel
	SalesChannel *SalesChannelSummary `json:"SalesChannel,omitempty"`

	// source
	Source *SourceSummary `json:"Source,omitempty"`

	// strip phone formatting
	StripPhoneFormatting bool `json:"StripPhoneFormatting,omitempty"`

	// transact as household
	TransactAsHousehold bool `json:"TransactAsHousehold,omitempty"`

	// transact as household creditee
	TransactAsHouseholdCreditee bool `json:"TransactAsHouseholdCreditee,omitempty"`

	// updated by
	UpdatedBy string `json:"UpdatedBy,omitempty"`

	// updated date time
	// Format: date-time
	UpdatedDateTime *strfmt.DateTime `json:"UpdatedDateTime,omitempty"`

	// worker
	Worker *Entity `json:"Worker,omitempty"`
}

// Validate validates this contribution import set
func (m *ContributionImportSet) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccountMatchKeyword(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBatchType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBillingSchedule(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateBillingType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCampaign(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateContributionDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedDateTime(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCrediteeType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultConstituentType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultHouseholdConstituentType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDefaultOriginalSource(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateDesignation(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFund(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePaymentMethod(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSalesChannel(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSource(formats); err != nil {
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

func (m *ContributionImportSet) validateAccountMatchKeyword(formats strfmt.Registry) error {
	if swag.IsZero(m.AccountMatchKeyword) { // not required
		return nil
	}

	if m.AccountMatchKeyword != nil {
		if err := m.AccountMatchKeyword.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AccountMatchKeyword")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AccountMatchKeyword")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateBatchType(formats strfmt.Registry) error {
	if swag.IsZero(m.BatchType) { // not required
		return nil
	}

	if m.BatchType != nil {
		if err := m.BatchType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BatchType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BatchType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateBillingSchedule(formats strfmt.Registry) error {
	if swag.IsZero(m.BillingSchedule) { // not required
		return nil
	}

	if m.BillingSchedule != nil {
		if err := m.BillingSchedule.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BillingSchedule")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BillingSchedule")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateBillingType(formats strfmt.Registry) error {
	if swag.IsZero(m.BillingType) { // not required
		return nil
	}

	if m.BillingType != nil {
		if err := m.BillingType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BillingType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BillingType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateCampaign(formats strfmt.Registry) error {
	if swag.IsZero(m.Campaign) { // not required
		return nil
	}

	if m.Campaign != nil {
		if err := m.Campaign.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Campaign")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Campaign")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateContributionDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.ContributionDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("ContributionDateTime", "body", "date-time", m.ContributionDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ContributionImportSet) validateCreatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.CreatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("CreatedDateTime", "body", "date-time", m.CreatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ContributionImportSet) validateCrediteeType(formats strfmt.Registry) error {
	if swag.IsZero(m.CrediteeType) { // not required
		return nil
	}

	if m.CrediteeType != nil {
		if err := m.CrediteeType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CrediteeType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CrediteeType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateDefaultConstituentType(formats strfmt.Registry) error {
	if swag.IsZero(m.DefaultConstituentType) { // not required
		return nil
	}

	if m.DefaultConstituentType != nil {
		if err := m.DefaultConstituentType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultConstituentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultConstituentType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateDefaultHouseholdConstituentType(formats strfmt.Registry) error {
	if swag.IsZero(m.DefaultHouseholdConstituentType) { // not required
		return nil
	}

	if m.DefaultHouseholdConstituentType != nil {
		if err := m.DefaultHouseholdConstituentType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultHouseholdConstituentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultHouseholdConstituentType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateDefaultOriginalSource(formats strfmt.Registry) error {
	if swag.IsZero(m.DefaultOriginalSource) { // not required
		return nil
	}

	if m.DefaultOriginalSource != nil {
		if err := m.DefaultOriginalSource.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultOriginalSource")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultOriginalSource")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateDesignation(formats strfmt.Registry) error {
	if swag.IsZero(m.Designation) { // not required
		return nil
	}

	if m.Designation != nil {
		if err := m.Designation.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Designation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Designation")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateFund(formats strfmt.Registry) error {
	if swag.IsZero(m.Fund) { // not required
		return nil
	}

	if m.Fund != nil {
		if err := m.Fund.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Fund")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Fund")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validatePaymentMethod(formats strfmt.Registry) error {
	if swag.IsZero(m.PaymentMethod) { // not required
		return nil
	}

	if m.PaymentMethod != nil {
		if err := m.PaymentMethod.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PaymentMethod")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PaymentMethod")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateSalesChannel(formats strfmt.Registry) error {
	if swag.IsZero(m.SalesChannel) { // not required
		return nil
	}

	if m.SalesChannel != nil {
		if err := m.SalesChannel.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SalesChannel")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SalesChannel")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateSource(formats strfmt.Registry) error {
	if swag.IsZero(m.Source) { // not required
		return nil
	}

	if m.Source != nil {
		if err := m.Source.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Source")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Source")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) validateUpdatedDateTime(formats strfmt.Registry) error {
	if swag.IsZero(m.UpdatedDateTime) { // not required
		return nil
	}

	if err := validate.FormatOf("UpdatedDateTime", "body", "date-time", m.UpdatedDateTime.String(), formats); err != nil {
		return err
	}

	return nil
}

func (m *ContributionImportSet) validateWorker(formats strfmt.Registry) error {
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

// ContextValidate validate this contribution import set based on the context it is used
func (m *ContributionImportSet) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccountMatchKeyword(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBatchType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBillingSchedule(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateBillingType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCampaign(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCrediteeType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDefaultConstituentType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDefaultHouseholdConstituentType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDefaultOriginalSource(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateDesignation(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFund(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePaymentMethod(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSalesChannel(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateSource(ctx, formats); err != nil {
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

func (m *ContributionImportSet) contextValidateAccountMatchKeyword(ctx context.Context, formats strfmt.Registry) error {

	if m.AccountMatchKeyword != nil {

		if swag.IsZero(m.AccountMatchKeyword) { // not required
			return nil
		}

		if err := m.AccountMatchKeyword.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("AccountMatchKeyword")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("AccountMatchKeyword")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateBatchType(ctx context.Context, formats strfmt.Registry) error {

	if m.BatchType != nil {

		if swag.IsZero(m.BatchType) { // not required
			return nil
		}

		if err := m.BatchType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BatchType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BatchType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateBillingSchedule(ctx context.Context, formats strfmt.Registry) error {

	if m.BillingSchedule != nil {

		if swag.IsZero(m.BillingSchedule) { // not required
			return nil
		}

		if err := m.BillingSchedule.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BillingSchedule")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BillingSchedule")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateBillingType(ctx context.Context, formats strfmt.Registry) error {

	if m.BillingType != nil {

		if swag.IsZero(m.BillingType) { // not required
			return nil
		}

		if err := m.BillingType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("BillingType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("BillingType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateCampaign(ctx context.Context, formats strfmt.Registry) error {

	if m.Campaign != nil {

		if swag.IsZero(m.Campaign) { // not required
			return nil
		}

		if err := m.Campaign.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Campaign")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Campaign")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateCrediteeType(ctx context.Context, formats strfmt.Registry) error {

	if m.CrediteeType != nil {

		if swag.IsZero(m.CrediteeType) { // not required
			return nil
		}

		if err := m.CrediteeType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("CrediteeType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("CrediteeType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateDefaultConstituentType(ctx context.Context, formats strfmt.Registry) error {

	if m.DefaultConstituentType != nil {

		if swag.IsZero(m.DefaultConstituentType) { // not required
			return nil
		}

		if err := m.DefaultConstituentType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultConstituentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultConstituentType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateDefaultHouseholdConstituentType(ctx context.Context, formats strfmt.Registry) error {

	if m.DefaultHouseholdConstituentType != nil {

		if swag.IsZero(m.DefaultHouseholdConstituentType) { // not required
			return nil
		}

		if err := m.DefaultHouseholdConstituentType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultHouseholdConstituentType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultHouseholdConstituentType")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateDefaultOriginalSource(ctx context.Context, formats strfmt.Registry) error {

	if m.DefaultOriginalSource != nil {

		if swag.IsZero(m.DefaultOriginalSource) { // not required
			return nil
		}

		if err := m.DefaultOriginalSource.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("DefaultOriginalSource")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("DefaultOriginalSource")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateDesignation(ctx context.Context, formats strfmt.Registry) error {

	if m.Designation != nil {

		if swag.IsZero(m.Designation) { // not required
			return nil
		}

		if err := m.Designation.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Designation")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Designation")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateFund(ctx context.Context, formats strfmt.Registry) error {

	if m.Fund != nil {

		if swag.IsZero(m.Fund) { // not required
			return nil
		}

		if err := m.Fund.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Fund")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Fund")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidatePaymentMethod(ctx context.Context, formats strfmt.Registry) error {

	if m.PaymentMethod != nil {

		if swag.IsZero(m.PaymentMethod) { // not required
			return nil
		}

		if err := m.PaymentMethod.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("PaymentMethod")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("PaymentMethod")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateSalesChannel(ctx context.Context, formats strfmt.Registry) error {

	if m.SalesChannel != nil {

		if swag.IsZero(m.SalesChannel) { // not required
			return nil
		}

		if err := m.SalesChannel.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("SalesChannel")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("SalesChannel")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateSource(ctx context.Context, formats strfmt.Registry) error {

	if m.Source != nil {

		if swag.IsZero(m.Source) { // not required
			return nil
		}

		if err := m.Source.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("Source")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("Source")
			}
			return err
		}
	}

	return nil
}

func (m *ContributionImportSet) contextValidateWorker(ctx context.Context, formats strfmt.Registry) error {

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
func (m *ContributionImportSet) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ContributionImportSet) UnmarshalBinary(b []byte) error {
	var res ContributionImportSet
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
