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

// NewPriceTypeReasonsGetAllParams creates a new PriceTypeReasonsGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPriceTypeReasonsGetAllParams() *PriceTypeReasonsGetAllParams {
	return &PriceTypeReasonsGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPriceTypeReasonsGetAllParamsWithTimeout creates a new PriceTypeReasonsGetAllParams object
// with the ability to set a timeout on a request.
func NewPriceTypeReasonsGetAllParamsWithTimeout(timeout time.Duration) *PriceTypeReasonsGetAllParams {
	return &PriceTypeReasonsGetAllParams{
		timeout: timeout,
	}
}

// NewPriceTypeReasonsGetAllParamsWithContext creates a new PriceTypeReasonsGetAllParams object
// with the ability to set a context for a request.
func NewPriceTypeReasonsGetAllParamsWithContext(ctx context.Context) *PriceTypeReasonsGetAllParams {
	return &PriceTypeReasonsGetAllParams{
		Context: ctx,
	}
}

// NewPriceTypeReasonsGetAllParamsWithHTTPClient creates a new PriceTypeReasonsGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewPriceTypeReasonsGetAllParamsWithHTTPClient(client *http.Client) *PriceTypeReasonsGetAllParams {
	return &PriceTypeReasonsGetAllParams{
		HTTPClient: client,
	}
}

/*
PriceTypeReasonsGetAllParams contains all the parameters to send to the API endpoint

	for the price type reasons get all operation.

	Typically these are written to a http.Request.
*/
type PriceTypeReasonsGetAllParams struct {

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the price type reasons get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceTypeReasonsGetAllParams) WithDefaults() *PriceTypeReasonsGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the price type reasons get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceTypeReasonsGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) WithTimeout(timeout time.Duration) *PriceTypeReasonsGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) WithContext(ctx context.Context) *PriceTypeReasonsGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) WithHTTPClient(client *http.Client) *PriceTypeReasonsGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMaintenanceMode adds the maintenanceMode to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) WithMaintenanceMode(maintenanceMode *string) *PriceTypeReasonsGetAllParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the price type reasons get all params
func (o *PriceTypeReasonsGetAllParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *PriceTypeReasonsGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

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