// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

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

// NewConstituenciesGetParams creates a new ConstituenciesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituenciesGetParams() *ConstituenciesGetParams {
	return &ConstituenciesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituenciesGetParamsWithTimeout creates a new ConstituenciesGetParams object
// with the ability to set a timeout on a request.
func NewConstituenciesGetParamsWithTimeout(timeout time.Duration) *ConstituenciesGetParams {
	return &ConstituenciesGetParams{
		timeout: timeout,
	}
}

// NewConstituenciesGetParamsWithContext creates a new ConstituenciesGetParams object
// with the ability to set a context for a request.
func NewConstituenciesGetParamsWithContext(ctx context.Context) *ConstituenciesGetParams {
	return &ConstituenciesGetParams{
		Context: ctx,
	}
}

// NewConstituenciesGetParamsWithHTTPClient creates a new ConstituenciesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituenciesGetParamsWithHTTPClient(client *http.Client) *ConstituenciesGetParams {
	return &ConstituenciesGetParams{
		HTTPClient: client,
	}
}

/*
ConstituenciesGetParams contains all the parameters to send to the API endpoint

	for the constituencies get operation.

	Typically these are written to a http.Request.
*/
type ConstituenciesGetParams struct {

	// ConstituencyID.
	ConstituencyID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituencies get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituenciesGetParams) WithDefaults() *ConstituenciesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituencies get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituenciesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituencies get params
func (o *ConstituenciesGetParams) WithTimeout(timeout time.Duration) *ConstituenciesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituencies get params
func (o *ConstituenciesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituencies get params
func (o *ConstituenciesGetParams) WithContext(ctx context.Context) *ConstituenciesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituencies get params
func (o *ConstituenciesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituencies get params
func (o *ConstituenciesGetParams) WithHTTPClient(client *http.Client) *ConstituenciesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituencies get params
func (o *ConstituenciesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConstituencyID adds the constituencyID to the constituencies get params
func (o *ConstituenciesGetParams) WithConstituencyID(constituencyID string) *ConstituenciesGetParams {
	o.SetConstituencyID(constituencyID)
	return o
}

// SetConstituencyID adds the constituencyId to the constituencies get params
func (o *ConstituenciesGetParams) SetConstituencyID(constituencyID string) {
	o.ConstituencyID = constituencyID
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituenciesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param constituencyId
	if err := r.SetPathParam("constituencyId", o.ConstituencyID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}