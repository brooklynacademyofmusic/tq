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

// NewResourceCategoriesGetAllParams creates a new ResourceCategoriesGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewResourceCategoriesGetAllParams() *ResourceCategoriesGetAllParams {
	return &ResourceCategoriesGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewResourceCategoriesGetAllParamsWithTimeout creates a new ResourceCategoriesGetAllParams object
// with the ability to set a timeout on a request.
func NewResourceCategoriesGetAllParamsWithTimeout(timeout time.Duration) *ResourceCategoriesGetAllParams {
	return &ResourceCategoriesGetAllParams{
		timeout: timeout,
	}
}

// NewResourceCategoriesGetAllParamsWithContext creates a new ResourceCategoriesGetAllParams object
// with the ability to set a context for a request.
func NewResourceCategoriesGetAllParamsWithContext(ctx context.Context) *ResourceCategoriesGetAllParams {
	return &ResourceCategoriesGetAllParams{
		Context: ctx,
	}
}

// NewResourceCategoriesGetAllParamsWithHTTPClient creates a new ResourceCategoriesGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewResourceCategoriesGetAllParamsWithHTTPClient(client *http.Client) *ResourceCategoriesGetAllParams {
	return &ResourceCategoriesGetAllParams{
		HTTPClient: client,
	}
}

/*
ResourceCategoriesGetAllParams contains all the parameters to send to the API endpoint

	for the resource categories get all operation.

	Typically these are written to a http.Request.
*/
type ResourceCategoriesGetAllParams struct {

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the resource categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResourceCategoriesGetAllParams) WithDefaults() *ResourceCategoriesGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the resource categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResourceCategoriesGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) WithTimeout(timeout time.Duration) *ResourceCategoriesGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) WithContext(ctx context.Context) *ResourceCategoriesGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) WithHTTPClient(client *http.Client) *ResourceCategoriesGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMaintenanceMode adds the maintenanceMode to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) WithMaintenanceMode(maintenanceMode *string) *ResourceCategoriesGetAllParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the resource categories get all params
func (o *ResourceCategoriesGetAllParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *ResourceCategoriesGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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