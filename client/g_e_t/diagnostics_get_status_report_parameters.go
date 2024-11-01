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

// NewDiagnosticsGetStatusReportParams creates a new DiagnosticsGetStatusReportParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDiagnosticsGetStatusReportParams() *DiagnosticsGetStatusReportParams {
	return &DiagnosticsGetStatusReportParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDiagnosticsGetStatusReportParamsWithTimeout creates a new DiagnosticsGetStatusReportParams object
// with the ability to set a timeout on a request.
func NewDiagnosticsGetStatusReportParamsWithTimeout(timeout time.Duration) *DiagnosticsGetStatusReportParams {
	return &DiagnosticsGetStatusReportParams{
		timeout: timeout,
	}
}

// NewDiagnosticsGetStatusReportParamsWithContext creates a new DiagnosticsGetStatusReportParams object
// with the ability to set a context for a request.
func NewDiagnosticsGetStatusReportParamsWithContext(ctx context.Context) *DiagnosticsGetStatusReportParams {
	return &DiagnosticsGetStatusReportParams{
		Context: ctx,
	}
}

// NewDiagnosticsGetStatusReportParamsWithHTTPClient creates a new DiagnosticsGetStatusReportParams object
// with the ability to set a custom HTTPClient for a request.
func NewDiagnosticsGetStatusReportParamsWithHTTPClient(client *http.Client) *DiagnosticsGetStatusReportParams {
	return &DiagnosticsGetStatusReportParams{
		HTTPClient: client,
	}
}

/*
DiagnosticsGetStatusReportParams contains all the parameters to send to the API endpoint

	for the diagnostics get status report operation.

	Typically these are written to a http.Request.
*/
type DiagnosticsGetStatusReportParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the diagnostics get status report params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DiagnosticsGetStatusReportParams) WithDefaults() *DiagnosticsGetStatusReportParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the diagnostics get status report params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DiagnosticsGetStatusReportParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the diagnostics get status report params
func (o *DiagnosticsGetStatusReportParams) WithTimeout(timeout time.Duration) *DiagnosticsGetStatusReportParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the diagnostics get status report params
func (o *DiagnosticsGetStatusReportParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the diagnostics get status report params
func (o *DiagnosticsGetStatusReportParams) WithContext(ctx context.Context) *DiagnosticsGetStatusReportParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the diagnostics get status report params
func (o *DiagnosticsGetStatusReportParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the diagnostics get status report params
func (o *DiagnosticsGetStatusReportParams) WithHTTPClient(client *http.Client) *DiagnosticsGetStatusReportParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the diagnostics get status report params
func (o *DiagnosticsGetStatusReportParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *DiagnosticsGetStatusReportParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}