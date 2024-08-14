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

// NewEmarketIndicatorsGetParams creates a new EmarketIndicatorsGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewEmarketIndicatorsGetParams() *EmarketIndicatorsGetParams {
	return &EmarketIndicatorsGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewEmarketIndicatorsGetParamsWithTimeout creates a new EmarketIndicatorsGetParams object
// with the ability to set a timeout on a request.
func NewEmarketIndicatorsGetParamsWithTimeout(timeout time.Duration) *EmarketIndicatorsGetParams {
	return &EmarketIndicatorsGetParams{
		timeout: timeout,
	}
}

// NewEmarketIndicatorsGetParamsWithContext creates a new EmarketIndicatorsGetParams object
// with the ability to set a context for a request.
func NewEmarketIndicatorsGetParamsWithContext(ctx context.Context) *EmarketIndicatorsGetParams {
	return &EmarketIndicatorsGetParams{
		Context: ctx,
	}
}

// NewEmarketIndicatorsGetParamsWithHTTPClient creates a new EmarketIndicatorsGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewEmarketIndicatorsGetParamsWithHTTPClient(client *http.Client) *EmarketIndicatorsGetParams {
	return &EmarketIndicatorsGetParams{
		HTTPClient: client,
	}
}

/*
EmarketIndicatorsGetParams contains all the parameters to send to the API endpoint

	for the emarket indicators get operation.

	Typically these are written to a http.Request.
*/
type EmarketIndicatorsGetParams struct {

	// ID.
	ID string

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the emarket indicators get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EmarketIndicatorsGetParams) WithDefaults() *EmarketIndicatorsGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the emarket indicators get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EmarketIndicatorsGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) WithTimeout(timeout time.Duration) *EmarketIndicatorsGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) WithContext(ctx context.Context) *EmarketIndicatorsGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) WithHTTPClient(client *http.Client) *EmarketIndicatorsGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) WithID(id string) *EmarketIndicatorsGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) SetID(id string) {
	o.ID = id
}

// WithMaintenanceMode adds the maintenanceMode to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) WithMaintenanceMode(maintenanceMode *string) *EmarketIndicatorsGetParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the emarket indicators get params
func (o *EmarketIndicatorsGetParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *EmarketIndicatorsGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if o.MaintenanceMode != nil {

		// query param maintenanceMode
		var qrMaintenanceMode string

		if o.MaintenanceMode != nil {
			qrMaintenanceMode = *o.MaintenanceMode
		}
		qMaintenanceMode := qrMaintenanceMode
		if qMaintenanceMode != "" {

			if err := r.SetQueryParam("maintenanceMode", qMaintenanceMode); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}