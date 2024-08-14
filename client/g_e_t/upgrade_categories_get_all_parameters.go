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

// NewUpgradeCategoriesGetAllParams creates a new UpgradeCategoriesGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpgradeCategoriesGetAllParams() *UpgradeCategoriesGetAllParams {
	return &UpgradeCategoriesGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpgradeCategoriesGetAllParamsWithTimeout creates a new UpgradeCategoriesGetAllParams object
// with the ability to set a timeout on a request.
func NewUpgradeCategoriesGetAllParamsWithTimeout(timeout time.Duration) *UpgradeCategoriesGetAllParams {
	return &UpgradeCategoriesGetAllParams{
		timeout: timeout,
	}
}

// NewUpgradeCategoriesGetAllParamsWithContext creates a new UpgradeCategoriesGetAllParams object
// with the ability to set a context for a request.
func NewUpgradeCategoriesGetAllParamsWithContext(ctx context.Context) *UpgradeCategoriesGetAllParams {
	return &UpgradeCategoriesGetAllParams{
		Context: ctx,
	}
}

// NewUpgradeCategoriesGetAllParamsWithHTTPClient creates a new UpgradeCategoriesGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpgradeCategoriesGetAllParamsWithHTTPClient(client *http.Client) *UpgradeCategoriesGetAllParams {
	return &UpgradeCategoriesGetAllParams{
		HTTPClient: client,
	}
}

/*
UpgradeCategoriesGetAllParams contains all the parameters to send to the API endpoint

	for the upgrade categories get all operation.

	Typically these are written to a http.Request.
*/
type UpgradeCategoriesGetAllParams struct {

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the upgrade categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpgradeCategoriesGetAllParams) WithDefaults() *UpgradeCategoriesGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the upgrade categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpgradeCategoriesGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) WithTimeout(timeout time.Duration) *UpgradeCategoriesGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) WithContext(ctx context.Context) *UpgradeCategoriesGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) WithHTTPClient(client *http.Client) *UpgradeCategoriesGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMaintenanceMode adds the maintenanceMode to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) WithMaintenanceMode(maintenanceMode *string) *UpgradeCategoriesGetAllParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the upgrade categories get all params
func (o *UpgradeCategoriesGetAllParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *UpgradeCategoriesGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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