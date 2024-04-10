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

// NewContactPointCategoryPurposesGetParams creates a new ContactPointCategoryPurposesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewContactPointCategoryPurposesGetParams() *ContactPointCategoryPurposesGetParams {
	return &ContactPointCategoryPurposesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewContactPointCategoryPurposesGetParamsWithTimeout creates a new ContactPointCategoryPurposesGetParams object
// with the ability to set a timeout on a request.
func NewContactPointCategoryPurposesGetParamsWithTimeout(timeout time.Duration) *ContactPointCategoryPurposesGetParams {
	return &ContactPointCategoryPurposesGetParams{
		timeout: timeout,
	}
}

// NewContactPointCategoryPurposesGetParamsWithContext creates a new ContactPointCategoryPurposesGetParams object
// with the ability to set a context for a request.
func NewContactPointCategoryPurposesGetParamsWithContext(ctx context.Context) *ContactPointCategoryPurposesGetParams {
	return &ContactPointCategoryPurposesGetParams{
		Context: ctx,
	}
}

// NewContactPointCategoryPurposesGetParamsWithHTTPClient creates a new ContactPointCategoryPurposesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewContactPointCategoryPurposesGetParamsWithHTTPClient(client *http.Client) *ContactPointCategoryPurposesGetParams {
	return &ContactPointCategoryPurposesGetParams{
		HTTPClient: client,
	}
}

/*
ContactPointCategoryPurposesGetParams contains all the parameters to send to the API endpoint

	for the contact point category purposes get operation.

	Typically these are written to a http.Request.
*/
type ContactPointCategoryPurposesGetParams struct {

	/* Filter.

	   Filter by user access (default: readwrite)
	*/
	Filter *string

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

// WithDefaults hydrates default values in the contact point category purposes get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContactPointCategoryPurposesGetParams) WithDefaults() *ContactPointCategoryPurposesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the contact point category purposes get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContactPointCategoryPurposesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) WithTimeout(timeout time.Duration) *ContactPointCategoryPurposesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) WithContext(ctx context.Context) *ContactPointCategoryPurposesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) WithHTTPClient(client *http.Client) *ContactPointCategoryPurposesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) WithFilter(filter *string) *ContactPointCategoryPurposesGetParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) WithID(id string) *ContactPointCategoryPurposesGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) SetID(id string) {
	o.ID = id
}

// WithMaintenanceMode adds the maintenanceMode to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) WithMaintenanceMode(maintenanceMode *string) *ContactPointCategoryPurposesGetParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the contact point category purposes get params
func (o *ContactPointCategoryPurposesGetParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *ContactPointCategoryPurposesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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