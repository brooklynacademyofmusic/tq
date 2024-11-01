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

// NewConstituenciesDeleteParams creates a new ConstituenciesDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituenciesDeleteParams() *ConstituenciesDeleteParams {
	return &ConstituenciesDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituenciesDeleteParamsWithTimeout creates a new ConstituenciesDeleteParams object
// with the ability to set a timeout on a request.
func NewConstituenciesDeleteParamsWithTimeout(timeout time.Duration) *ConstituenciesDeleteParams {
	return &ConstituenciesDeleteParams{
		timeout: timeout,
	}
}

// NewConstituenciesDeleteParamsWithContext creates a new ConstituenciesDeleteParams object
// with the ability to set a context for a request.
func NewConstituenciesDeleteParamsWithContext(ctx context.Context) *ConstituenciesDeleteParams {
	return &ConstituenciesDeleteParams{
		Context: ctx,
	}
}

// NewConstituenciesDeleteParamsWithHTTPClient creates a new ConstituenciesDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituenciesDeleteParamsWithHTTPClient(client *http.Client) *ConstituenciesDeleteParams {
	return &ConstituenciesDeleteParams{
		HTTPClient: client,
	}
}

/*
ConstituenciesDeleteParams contains all the parameters to send to the API endpoint

	for the constituencies delete operation.

	Typically these are written to a http.Request.
*/
type ConstituenciesDeleteParams struct {

	// ConstituencyID.
	ConstituencyID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituencies delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituenciesDeleteParams) WithDefaults() *ConstituenciesDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituencies delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituenciesDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituencies delete params
func (o *ConstituenciesDeleteParams) WithTimeout(timeout time.Duration) *ConstituenciesDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituencies delete params
func (o *ConstituenciesDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituencies delete params
func (o *ConstituenciesDeleteParams) WithContext(ctx context.Context) *ConstituenciesDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituencies delete params
func (o *ConstituenciesDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituencies delete params
func (o *ConstituenciesDeleteParams) WithHTTPClient(client *http.Client) *ConstituenciesDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituencies delete params
func (o *ConstituenciesDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConstituencyID adds the constituencyID to the constituencies delete params
func (o *ConstituenciesDeleteParams) WithConstituencyID(constituencyID string) *ConstituenciesDeleteParams {
	o.SetConstituencyID(constituencyID)
	return o
}

// SetConstituencyID adds the constituencyId to the constituencies delete params
func (o *ConstituenciesDeleteParams) SetConstituencyID(constituencyID string) {
	o.ConstituencyID = constituencyID
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituenciesDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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