// Code generated by go-swagger; DO NOT EDIT.

package h_e_a_d

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

// NewDiagnosticsPingParams creates a new DiagnosticsPingParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDiagnosticsPingParams() *DiagnosticsPingParams {
	return &DiagnosticsPingParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDiagnosticsPingParamsWithTimeout creates a new DiagnosticsPingParams object
// with the ability to set a timeout on a request.
func NewDiagnosticsPingParamsWithTimeout(timeout time.Duration) *DiagnosticsPingParams {
	return &DiagnosticsPingParams{
		timeout: timeout,
	}
}

// NewDiagnosticsPingParamsWithContext creates a new DiagnosticsPingParams object
// with the ability to set a context for a request.
func NewDiagnosticsPingParamsWithContext(ctx context.Context) *DiagnosticsPingParams {
	return &DiagnosticsPingParams{
		Context: ctx,
	}
}

// NewDiagnosticsPingParamsWithHTTPClient creates a new DiagnosticsPingParams object
// with the ability to set a custom HTTPClient for a request.
func NewDiagnosticsPingParamsWithHTTPClient(client *http.Client) *DiagnosticsPingParams {
	return &DiagnosticsPingParams{
		HTTPClient: client,
	}
}

/*
DiagnosticsPingParams contains all the parameters to send to the API endpoint

	for the diagnostics ping operation.

	Typically these are written to a http.Request.
*/
type DiagnosticsPingParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the diagnostics ping params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DiagnosticsPingParams) WithDefaults() *DiagnosticsPingParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the diagnostics ping params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DiagnosticsPingParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the diagnostics ping params
func (o *DiagnosticsPingParams) WithTimeout(timeout time.Duration) *DiagnosticsPingParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the diagnostics ping params
func (o *DiagnosticsPingParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the diagnostics ping params
func (o *DiagnosticsPingParams) WithContext(ctx context.Context) *DiagnosticsPingParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the diagnostics ping params
func (o *DiagnosticsPingParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the diagnostics ping params
func (o *DiagnosticsPingParams) WithHTTPClient(client *http.Client) *DiagnosticsPingParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the diagnostics ping params
func (o *DiagnosticsPingParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *DiagnosticsPingParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}