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

// NewDiagnosticsGetStatusParams creates a new DiagnosticsGetStatusParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDiagnosticsGetStatusParams() *DiagnosticsGetStatusParams {
	return &DiagnosticsGetStatusParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDiagnosticsGetStatusParamsWithTimeout creates a new DiagnosticsGetStatusParams object
// with the ability to set a timeout on a request.
func NewDiagnosticsGetStatusParamsWithTimeout(timeout time.Duration) *DiagnosticsGetStatusParams {
	return &DiagnosticsGetStatusParams{
		timeout: timeout,
	}
}

// NewDiagnosticsGetStatusParamsWithContext creates a new DiagnosticsGetStatusParams object
// with the ability to set a context for a request.
func NewDiagnosticsGetStatusParamsWithContext(ctx context.Context) *DiagnosticsGetStatusParams {
	return &DiagnosticsGetStatusParams{
		Context: ctx,
	}
}

// NewDiagnosticsGetStatusParamsWithHTTPClient creates a new DiagnosticsGetStatusParams object
// with the ability to set a custom HTTPClient for a request.
func NewDiagnosticsGetStatusParamsWithHTTPClient(client *http.Client) *DiagnosticsGetStatusParams {
	return &DiagnosticsGetStatusParams{
		HTTPClient: client,
	}
}

/*
DiagnosticsGetStatusParams contains all the parameters to send to the API endpoint

	for the diagnostics get status operation.

	Typically these are written to a http.Request.
*/
type DiagnosticsGetStatusParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the diagnostics get status params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DiagnosticsGetStatusParams) WithDefaults() *DiagnosticsGetStatusParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the diagnostics get status params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DiagnosticsGetStatusParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the diagnostics get status params
func (o *DiagnosticsGetStatusParams) WithTimeout(timeout time.Duration) *DiagnosticsGetStatusParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the diagnostics get status params
func (o *DiagnosticsGetStatusParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the diagnostics get status params
func (o *DiagnosticsGetStatusParams) WithContext(ctx context.Context) *DiagnosticsGetStatusParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the diagnostics get status params
func (o *DiagnosticsGetStatusParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the diagnostics get status params
func (o *DiagnosticsGetStatusParams) WithHTTPClient(client *http.Client) *DiagnosticsGetStatusParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the diagnostics get status params
func (o *DiagnosticsGetStatusParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *DiagnosticsGetStatusParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}