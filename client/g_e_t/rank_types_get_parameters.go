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

// NewRankTypesGetParams creates a new RankTypesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewRankTypesGetParams() *RankTypesGetParams {
	return &RankTypesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewRankTypesGetParamsWithTimeout creates a new RankTypesGetParams object
// with the ability to set a timeout on a request.
func NewRankTypesGetParamsWithTimeout(timeout time.Duration) *RankTypesGetParams {
	return &RankTypesGetParams{
		timeout: timeout,
	}
}

// NewRankTypesGetParamsWithContext creates a new RankTypesGetParams object
// with the ability to set a context for a request.
func NewRankTypesGetParamsWithContext(ctx context.Context) *RankTypesGetParams {
	return &RankTypesGetParams{
		Context: ctx,
	}
}

// NewRankTypesGetParamsWithHTTPClient creates a new RankTypesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewRankTypesGetParamsWithHTTPClient(client *http.Client) *RankTypesGetParams {
	return &RankTypesGetParams{
		HTTPClient: client,
	}
}

/*
RankTypesGetParams contains all the parameters to send to the API endpoint

	for the rank types get operation.

	Typically these are written to a http.Request.
*/
type RankTypesGetParams struct {

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

// WithDefaults hydrates default values in the rank types get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RankTypesGetParams) WithDefaults() *RankTypesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the rank types get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *RankTypesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the rank types get params
func (o *RankTypesGetParams) WithTimeout(timeout time.Duration) *RankTypesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the rank types get params
func (o *RankTypesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the rank types get params
func (o *RankTypesGetParams) WithContext(ctx context.Context) *RankTypesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the rank types get params
func (o *RankTypesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the rank types get params
func (o *RankTypesGetParams) WithHTTPClient(client *http.Client) *RankTypesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the rank types get params
func (o *RankTypesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the rank types get params
func (o *RankTypesGetParams) WithFilter(filter *string) *RankTypesGetParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the rank types get params
func (o *RankTypesGetParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithID adds the id to the rank types get params
func (o *RankTypesGetParams) WithID(id string) *RankTypesGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the rank types get params
func (o *RankTypesGetParams) SetID(id string) {
	o.ID = id
}

// WithMaintenanceMode adds the maintenanceMode to the rank types get params
func (o *RankTypesGetParams) WithMaintenanceMode(maintenanceMode *string) *RankTypesGetParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the rank types get params
func (o *RankTypesGetParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *RankTypesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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