// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// NewBookingTemplatesUpdateParams creates a new BookingTemplatesUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBookingTemplatesUpdateParams() *BookingTemplatesUpdateParams {
	return &BookingTemplatesUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBookingTemplatesUpdateParamsWithTimeout creates a new BookingTemplatesUpdateParams object
// with the ability to set a timeout on a request.
func NewBookingTemplatesUpdateParamsWithTimeout(timeout time.Duration) *BookingTemplatesUpdateParams {
	return &BookingTemplatesUpdateParams{
		timeout: timeout,
	}
}

// NewBookingTemplatesUpdateParamsWithContext creates a new BookingTemplatesUpdateParams object
// with the ability to set a context for a request.
func NewBookingTemplatesUpdateParamsWithContext(ctx context.Context) *BookingTemplatesUpdateParams {
	return &BookingTemplatesUpdateParams{
		Context: ctx,
	}
}

// NewBookingTemplatesUpdateParamsWithHTTPClient creates a new BookingTemplatesUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewBookingTemplatesUpdateParamsWithHTTPClient(client *http.Client) *BookingTemplatesUpdateParams {
	return &BookingTemplatesUpdateParams{
		HTTPClient: client,
	}
}

/*
BookingTemplatesUpdateParams contains all the parameters to send to the API endpoint

	for the booking templates update operation.

	Typically these are written to a http.Request.
*/
type BookingTemplatesUpdateParams struct {

	// BookingTemplate.
	BookingTemplate *models.BookingTemplate

	// BookingTemplateID.
	BookingTemplateID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the booking templates update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BookingTemplatesUpdateParams) WithDefaults() *BookingTemplatesUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the booking templates update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BookingTemplatesUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the booking templates update params
func (o *BookingTemplatesUpdateParams) WithTimeout(timeout time.Duration) *BookingTemplatesUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the booking templates update params
func (o *BookingTemplatesUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the booking templates update params
func (o *BookingTemplatesUpdateParams) WithContext(ctx context.Context) *BookingTemplatesUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the booking templates update params
func (o *BookingTemplatesUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the booking templates update params
func (o *BookingTemplatesUpdateParams) WithHTTPClient(client *http.Client) *BookingTemplatesUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the booking templates update params
func (o *BookingTemplatesUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBookingTemplate adds the bookingTemplate to the booking templates update params
func (o *BookingTemplatesUpdateParams) WithBookingTemplate(bookingTemplate *models.BookingTemplate) *BookingTemplatesUpdateParams {
	o.SetBookingTemplate(bookingTemplate)
	return o
}

// SetBookingTemplate adds the bookingTemplate to the booking templates update params
func (o *BookingTemplatesUpdateParams) SetBookingTemplate(bookingTemplate *models.BookingTemplate) {
	o.BookingTemplate = bookingTemplate
}

// WithBookingTemplateID adds the bookingTemplateID to the booking templates update params
func (o *BookingTemplatesUpdateParams) WithBookingTemplateID(bookingTemplateID string) *BookingTemplatesUpdateParams {
	o.SetBookingTemplateID(bookingTemplateID)
	return o
}

// SetBookingTemplateID adds the bookingTemplateId to the booking templates update params
func (o *BookingTemplatesUpdateParams) SetBookingTemplateID(bookingTemplateID string) {
	o.BookingTemplateID = bookingTemplateID
}

// WriteToRequest writes these params to a swagger request
func (o *BookingTemplatesUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.BookingTemplate != nil {
		if err := r.SetBodyParam(o.BookingTemplate); err != nil {
			return err
		}
	}

	// path param bookingTemplateId
	if err := r.SetPathParam("bookingTemplateId", o.BookingTemplateID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}