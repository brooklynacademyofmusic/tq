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

// NewDesignsGetAllParams creates a new DesignsGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDesignsGetAllParams() *DesignsGetAllParams {
	return &DesignsGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDesignsGetAllParamsWithTimeout creates a new DesignsGetAllParams object
// with the ability to set a timeout on a request.
func NewDesignsGetAllParamsWithTimeout(timeout time.Duration) *DesignsGetAllParams {
	return &DesignsGetAllParams{
		timeout: timeout,
	}
}

// NewDesignsGetAllParamsWithContext creates a new DesignsGetAllParams object
// with the ability to set a context for a request.
func NewDesignsGetAllParamsWithContext(ctx context.Context) *DesignsGetAllParams {
	return &DesignsGetAllParams{
		Context: ctx,
	}
}

// NewDesignsGetAllParamsWithHTTPClient creates a new DesignsGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewDesignsGetAllParamsWithHTTPClient(client *http.Client) *DesignsGetAllParams {
	return &DesignsGetAllParams{
		HTTPClient: client,
	}
}

/*
DesignsGetAllParams contains all the parameters to send to the API endpoint

	for the designs get all operation.

	Typically these are written to a http.Request.
*/
type DesignsGetAllParams struct {

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the designs get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DesignsGetAllParams) WithDefaults() *DesignsGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the designs get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DesignsGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the designs get all params
func (o *DesignsGetAllParams) WithTimeout(timeout time.Duration) *DesignsGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the designs get all params
func (o *DesignsGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the designs get all params
func (o *DesignsGetAllParams) WithContext(ctx context.Context) *DesignsGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the designs get all params
func (o *DesignsGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the designs get all params
func (o *DesignsGetAllParams) WithHTTPClient(client *http.Client) *DesignsGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the designs get all params
func (o *DesignsGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMaintenanceMode adds the maintenanceMode to the designs get all params
func (o *DesignsGetAllParams) WithMaintenanceMode(maintenanceMode *string) *DesignsGetAllParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the designs get all params
func (o *DesignsGetAllParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *DesignsGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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