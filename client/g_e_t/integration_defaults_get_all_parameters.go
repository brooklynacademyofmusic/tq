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

// NewIntegrationDefaultsGetAllParams creates a new IntegrationDefaultsGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewIntegrationDefaultsGetAllParams() *IntegrationDefaultsGetAllParams {
	return &IntegrationDefaultsGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewIntegrationDefaultsGetAllParamsWithTimeout creates a new IntegrationDefaultsGetAllParams object
// with the ability to set a timeout on a request.
func NewIntegrationDefaultsGetAllParamsWithTimeout(timeout time.Duration) *IntegrationDefaultsGetAllParams {
	return &IntegrationDefaultsGetAllParams{
		timeout: timeout,
	}
}

// NewIntegrationDefaultsGetAllParamsWithContext creates a new IntegrationDefaultsGetAllParams object
// with the ability to set a context for a request.
func NewIntegrationDefaultsGetAllParamsWithContext(ctx context.Context) *IntegrationDefaultsGetAllParams {
	return &IntegrationDefaultsGetAllParams{
		Context: ctx,
	}
}

// NewIntegrationDefaultsGetAllParamsWithHTTPClient creates a new IntegrationDefaultsGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewIntegrationDefaultsGetAllParamsWithHTTPClient(client *http.Client) *IntegrationDefaultsGetAllParams {
	return &IntegrationDefaultsGetAllParams{
		HTTPClient: client,
	}
}

/*
IntegrationDefaultsGetAllParams contains all the parameters to send to the API endpoint

	for the integration defaults get all operation.

	Typically these are written to a http.Request.
*/
type IntegrationDefaultsGetAllParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the integration defaults get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntegrationDefaultsGetAllParams) WithDefaults() *IntegrationDefaultsGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the integration defaults get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *IntegrationDefaultsGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the integration defaults get all params
func (o *IntegrationDefaultsGetAllParams) WithTimeout(timeout time.Duration) *IntegrationDefaultsGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the integration defaults get all params
func (o *IntegrationDefaultsGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the integration defaults get all params
func (o *IntegrationDefaultsGetAllParams) WithContext(ctx context.Context) *IntegrationDefaultsGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the integration defaults get all params
func (o *IntegrationDefaultsGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the integration defaults get all params
func (o *IntegrationDefaultsGetAllParams) WithHTTPClient(client *http.Client) *IntegrationDefaultsGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the integration defaults get all params
func (o *IntegrationDefaultsGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *IntegrationDefaultsGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}