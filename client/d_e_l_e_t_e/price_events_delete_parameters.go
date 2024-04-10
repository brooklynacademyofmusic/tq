// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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
)

// NewPriceEventsDeleteParams creates a new PriceEventsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPriceEventsDeleteParams() *PriceEventsDeleteParams {
	return &PriceEventsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPriceEventsDeleteParamsWithTimeout creates a new PriceEventsDeleteParams object
// with the ability to set a timeout on a request.
func NewPriceEventsDeleteParamsWithTimeout(timeout time.Duration) *PriceEventsDeleteParams {
	return &PriceEventsDeleteParams{
		timeout: timeout,
	}
}

// NewPriceEventsDeleteParamsWithContext creates a new PriceEventsDeleteParams object
// with the ability to set a context for a request.
func NewPriceEventsDeleteParamsWithContext(ctx context.Context) *PriceEventsDeleteParams {
	return &PriceEventsDeleteParams{
		Context: ctx,
	}
}

// NewPriceEventsDeleteParamsWithHTTPClient creates a new PriceEventsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewPriceEventsDeleteParamsWithHTTPClient(client *http.Client) *PriceEventsDeleteParams {
	return &PriceEventsDeleteParams{
		HTTPClient: client,
	}
}

/*
PriceEventsDeleteParams contains all the parameters to send to the API endpoint

	for the price events delete operation.

	Typically these are written to a http.Request.
*/
type PriceEventsDeleteParams struct {

	// PriceEventID.
	PriceEventID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the price events delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceEventsDeleteParams) WithDefaults() *PriceEventsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the price events delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceEventsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the price events delete params
func (o *PriceEventsDeleteParams) WithTimeout(timeout time.Duration) *PriceEventsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the price events delete params
func (o *PriceEventsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the price events delete params
func (o *PriceEventsDeleteParams) WithContext(ctx context.Context) *PriceEventsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the price events delete params
func (o *PriceEventsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the price events delete params
func (o *PriceEventsDeleteParams) WithHTTPClient(client *http.Client) *PriceEventsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the price events delete params
func (o *PriceEventsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPriceEventID adds the priceEventID to the price events delete params
func (o *PriceEventsDeleteParams) WithPriceEventID(priceEventID string) *PriceEventsDeleteParams {
	o.SetPriceEventID(priceEventID)
	return o
}

// SetPriceEventID adds the priceEventId to the price events delete params
func (o *PriceEventsDeleteParams) SetPriceEventID(priceEventID string) {
	o.PriceEventID = priceEventID
}

// WriteToRequest writes these params to a swagger request
func (o *PriceEventsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param priceEventId
	if err := r.SetPathParam("priceEventId", o.PriceEventID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}