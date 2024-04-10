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

// NewContactPermissionCategoriesGetAllParams creates a new ContactPermissionCategoriesGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewContactPermissionCategoriesGetAllParams() *ContactPermissionCategoriesGetAllParams {
	return &ContactPermissionCategoriesGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewContactPermissionCategoriesGetAllParamsWithTimeout creates a new ContactPermissionCategoriesGetAllParams object
// with the ability to set a timeout on a request.
func NewContactPermissionCategoriesGetAllParamsWithTimeout(timeout time.Duration) *ContactPermissionCategoriesGetAllParams {
	return &ContactPermissionCategoriesGetAllParams{
		timeout: timeout,
	}
}

// NewContactPermissionCategoriesGetAllParamsWithContext creates a new ContactPermissionCategoriesGetAllParams object
// with the ability to set a context for a request.
func NewContactPermissionCategoriesGetAllParamsWithContext(ctx context.Context) *ContactPermissionCategoriesGetAllParams {
	return &ContactPermissionCategoriesGetAllParams{
		Context: ctx,
	}
}

// NewContactPermissionCategoriesGetAllParamsWithHTTPClient creates a new ContactPermissionCategoriesGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewContactPermissionCategoriesGetAllParamsWithHTTPClient(client *http.Client) *ContactPermissionCategoriesGetAllParams {
	return &ContactPermissionCategoriesGetAllParams{
		HTTPClient: client,
	}
}

/*
ContactPermissionCategoriesGetAllParams contains all the parameters to send to the API endpoint

	for the contact permission categories get all operation.

	Typically these are written to a http.Request.
*/
type ContactPermissionCategoriesGetAllParams struct {

	/* Filter.

	   Filter by user access (default: readwrite)
	*/
	Filter *string

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the contact permission categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContactPermissionCategoriesGetAllParams) WithDefaults() *ContactPermissionCategoriesGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the contact permission categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContactPermissionCategoriesGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) WithTimeout(timeout time.Duration) *ContactPermissionCategoriesGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) WithContext(ctx context.Context) *ContactPermissionCategoriesGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) WithHTTPClient(client *http.Client) *ContactPermissionCategoriesGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) WithFilter(filter *string) *ContactPermissionCategoriesGetAllParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithMaintenanceMode adds the maintenanceMode to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) WithMaintenanceMode(maintenanceMode *string) *ContactPermissionCategoriesGetAllParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the contact permission categories get all params
func (o *ContactPermissionCategoriesGetAllParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *ContactPermissionCategoriesGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
				return err
			}
		}
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