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

// NewUpgradeCategoriesGetParams creates a new UpgradeCategoriesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUpgradeCategoriesGetParams() *UpgradeCategoriesGetParams {
	return &UpgradeCategoriesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUpgradeCategoriesGetParamsWithTimeout creates a new UpgradeCategoriesGetParams object
// with the ability to set a timeout on a request.
func NewUpgradeCategoriesGetParamsWithTimeout(timeout time.Duration) *UpgradeCategoriesGetParams {
	return &UpgradeCategoriesGetParams{
		timeout: timeout,
	}
}

// NewUpgradeCategoriesGetParamsWithContext creates a new UpgradeCategoriesGetParams object
// with the ability to set a context for a request.
func NewUpgradeCategoriesGetParamsWithContext(ctx context.Context) *UpgradeCategoriesGetParams {
	return &UpgradeCategoriesGetParams{
		Context: ctx,
	}
}

// NewUpgradeCategoriesGetParamsWithHTTPClient creates a new UpgradeCategoriesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewUpgradeCategoriesGetParamsWithHTTPClient(client *http.Client) *UpgradeCategoriesGetParams {
	return &UpgradeCategoriesGetParams{
		HTTPClient: client,
	}
}

/*
UpgradeCategoriesGetParams contains all the parameters to send to the API endpoint

	for the upgrade categories get operation.

	Typically these are written to a http.Request.
*/
type UpgradeCategoriesGetParams struct {

	/* ID.

	   The id of the resource
	*/
	ID string

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the upgrade categories get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpgradeCategoriesGetParams) WithDefaults() *UpgradeCategoriesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the upgrade categories get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UpgradeCategoriesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) WithTimeout(timeout time.Duration) *UpgradeCategoriesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) WithContext(ctx context.Context) *UpgradeCategoriesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) WithHTTPClient(client *http.Client) *UpgradeCategoriesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) WithID(id string) *UpgradeCategoriesGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) SetID(id string) {
	o.ID = id
}

// WithMaintenanceMode adds the maintenanceMode to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) WithMaintenanceMode(maintenanceMode *string) *UpgradeCategoriesGetParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the upgrade categories get params
func (o *UpgradeCategoriesGetParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *UpgradeCategoriesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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