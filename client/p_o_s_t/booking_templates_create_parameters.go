// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// NewBookingTemplatesCreateParams creates a new BookingTemplatesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBookingTemplatesCreateParams() *BookingTemplatesCreateParams {
	return &BookingTemplatesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBookingTemplatesCreateParamsWithTimeout creates a new BookingTemplatesCreateParams object
// with the ability to set a timeout on a request.
func NewBookingTemplatesCreateParamsWithTimeout(timeout time.Duration) *BookingTemplatesCreateParams {
	return &BookingTemplatesCreateParams{
		timeout: timeout,
	}
}

// NewBookingTemplatesCreateParamsWithContext creates a new BookingTemplatesCreateParams object
// with the ability to set a context for a request.
func NewBookingTemplatesCreateParamsWithContext(ctx context.Context) *BookingTemplatesCreateParams {
	return &BookingTemplatesCreateParams{
		Context: ctx,
	}
}

// NewBookingTemplatesCreateParamsWithHTTPClient creates a new BookingTemplatesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewBookingTemplatesCreateParamsWithHTTPClient(client *http.Client) *BookingTemplatesCreateParams {
	return &BookingTemplatesCreateParams{
		HTTPClient: client,
	}
}

/*
BookingTemplatesCreateParams contains all the parameters to send to the API endpoint

	for the booking templates create operation.

	Typically these are written to a http.Request.
*/
type BookingTemplatesCreateParams struct {

	// BookingTemplate.
	BookingTemplate *models.BookingTemplate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the booking templates create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BookingTemplatesCreateParams) WithDefaults() *BookingTemplatesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the booking templates create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BookingTemplatesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the booking templates create params
func (o *BookingTemplatesCreateParams) WithTimeout(timeout time.Duration) *BookingTemplatesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the booking templates create params
func (o *BookingTemplatesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the booking templates create params
func (o *BookingTemplatesCreateParams) WithContext(ctx context.Context) *BookingTemplatesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the booking templates create params
func (o *BookingTemplatesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the booking templates create params
func (o *BookingTemplatesCreateParams) WithHTTPClient(client *http.Client) *BookingTemplatesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the booking templates create params
func (o *BookingTemplatesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBookingTemplate adds the bookingTemplate to the booking templates create params
func (o *BookingTemplatesCreateParams) WithBookingTemplate(bookingTemplate *models.BookingTemplate) *BookingTemplatesCreateParams {
	o.SetBookingTemplate(bookingTemplate)
	return o
}

// SetBookingTemplate adds the bookingTemplate to the booking templates create params
func (o *BookingTemplatesCreateParams) SetBookingTemplate(bookingTemplate *models.BookingTemplate) {
	o.BookingTemplate = bookingTemplate
}

// WriteToRequest writes these params to a swagger request
func (o *BookingTemplatesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.BookingTemplate != nil {
		if err := r.SetBodyParam(o.BookingTemplate); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}