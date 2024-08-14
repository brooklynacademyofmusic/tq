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

// NewOriginsDeleteParams creates a new OriginsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOriginsDeleteParams() *OriginsDeleteParams {
	return &OriginsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOriginsDeleteParamsWithTimeout creates a new OriginsDeleteParams object
// with the ability to set a timeout on a request.
func NewOriginsDeleteParamsWithTimeout(timeout time.Duration) *OriginsDeleteParams {
	return &OriginsDeleteParams{
		timeout: timeout,
	}
}

// NewOriginsDeleteParamsWithContext creates a new OriginsDeleteParams object
// with the ability to set a context for a request.
func NewOriginsDeleteParamsWithContext(ctx context.Context) *OriginsDeleteParams {
	return &OriginsDeleteParams{
		Context: ctx,
	}
}

// NewOriginsDeleteParamsWithHTTPClient creates a new OriginsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewOriginsDeleteParamsWithHTTPClient(client *http.Client) *OriginsDeleteParams {
	return &OriginsDeleteParams{
		HTTPClient: client,
	}
}

/*
OriginsDeleteParams contains all the parameters to send to the API endpoint

	for the origins delete operation.

	Typically these are written to a http.Request.
*/
type OriginsDeleteParams struct {

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the origins delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OriginsDeleteParams) WithDefaults() *OriginsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the origins delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OriginsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the origins delete params
func (o *OriginsDeleteParams) WithTimeout(timeout time.Duration) *OriginsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the origins delete params
func (o *OriginsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the origins delete params
func (o *OriginsDeleteParams) WithContext(ctx context.Context) *OriginsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the origins delete params
func (o *OriginsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the origins delete params
func (o *OriginsDeleteParams) WithHTTPClient(client *http.Client) *OriginsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the origins delete params
func (o *OriginsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the origins delete params
func (o *OriginsDeleteParams) WithID(id string) *OriginsDeleteParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the origins delete params
func (o *OriginsDeleteParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *OriginsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}