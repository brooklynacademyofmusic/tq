// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// EmailSendRequest email send request
//
// swagger:model EmailSendRequest
type EmailSendRequest struct {

	// attachments
	Attachments []*EmailAttachment `json:"Attachments"`

	// duplicate body as attachment
	DuplicateBodyAsAttachment bool `json:"DuplicateBodyAsAttachment,omitempty"`

	// duplicate body attachment name
	DuplicateBodyAttachmentName string `json:"DuplicateBodyAttachmentName,omitempty"`

	// email profile Id
	EmailProfileID int32 `json:"EmailProfileId,omitempty"`

	// embedded images
	EmbeddedImages []*EmailEmbeddedImage `json:"EmbeddedImages"`

	// from address
	FromAddress string `json:"FromAddress,omitempty"`

	// Html body
	HTMLBody string `json:"HtmlBody,omitempty"`

	// plain text body
	PlainTextBody string `json:"PlainTextBody,omitempty"`

	// recipient address
	RecipientAddress string `json:"RecipientAddress,omitempty"`

	// subject
	Subject string `json:"Subject,omitempty"`
}

// Validate validates this email send request
func (m *EmailSendRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAttachments(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEmbeddedImages(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EmailSendRequest) validateAttachments(formats strfmt.Registry) error {
	if swag.IsZero(m.Attachments) { // not required
		return nil
	}

	for i := 0; i < len(m.Attachments); i++ {
		if swag.IsZero(m.Attachments[i]) { // not required
			continue
		}

		if m.Attachments[i] != nil {
			if err := m.Attachments[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Attachments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Attachments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *EmailSendRequest) validateEmbeddedImages(formats strfmt.Registry) error {
	if swag.IsZero(m.EmbeddedImages) { // not required
		return nil
	}

	for i := 0; i < len(m.EmbeddedImages); i++ {
		if swag.IsZero(m.EmbeddedImages[i]) { // not required
			continue
		}

		if m.EmbeddedImages[i] != nil {
			if err := m.EmbeddedImages[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("EmbeddedImages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("EmbeddedImages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this email send request based on the context it is used
func (m *EmailSendRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAttachments(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateEmbeddedImages(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EmailSendRequest) contextValidateAttachments(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Attachments); i++ {

		if m.Attachments[i] != nil {

			if swag.IsZero(m.Attachments[i]) { // not required
				return nil
			}

			if err := m.Attachments[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("Attachments" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("Attachments" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *EmailSendRequest) contextValidateEmbeddedImages(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.EmbeddedImages); i++ {

		if m.EmbeddedImages[i] != nil {

			if swag.IsZero(m.EmbeddedImages[i]) { // not required
				return nil
			}

			if err := m.EmbeddedImages[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("EmbeddedImages" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("EmbeddedImages" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *EmailSendRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EmailSendRequest) UnmarshalBinary(b []byte) error {
	var res EmailSendRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}