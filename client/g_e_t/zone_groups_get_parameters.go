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

// NewZoneGroupsGetParams creates a new ZoneGroupsGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewZoneGroupsGetParams() *ZoneGroupsGetParams {
	return &ZoneGroupsGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewZoneGroupsGetParamsWithTimeout creates a new ZoneGroupsGetParams object
// with the ability to set a timeout on a request.
func NewZoneGroupsGetParamsWithTimeout(timeout time.Duration) *ZoneGroupsGetParams {
	return &ZoneGroupsGetParams{
		timeout: timeout,
	}
}

// NewZoneGroupsGetParamsWithContext creates a new ZoneGroupsGetParams object
// with the ability to set a context for a request.
func NewZoneGroupsGetParamsWithContext(ctx context.Context) *ZoneGroupsGetParams {
	return &ZoneGroupsGetParams{
		Context: ctx,
	}
}

// NewZoneGroupsGetParamsWithHTTPClient creates a new ZoneGroupsGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewZoneGroupsGetParamsWithHTTPClient(client *http.Client) *ZoneGroupsGetParams {
	return &ZoneGroupsGetParams{
		HTTPClient: client,
	}
}

/*
ZoneGroupsGetParams contains all the parameters to send to the API endpoint

	for the zone groups get operation.

	Typically these are written to a http.Request.
*/
type ZoneGroupsGetParams struct {

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

// WithDefaults hydrates default values in the zone groups get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ZoneGroupsGetParams) WithDefaults() *ZoneGroupsGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the zone groups get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ZoneGroupsGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the zone groups get params
func (o *ZoneGroupsGetParams) WithTimeout(timeout time.Duration) *ZoneGroupsGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the zone groups get params
func (o *ZoneGroupsGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the zone groups get params
func (o *ZoneGroupsGetParams) WithContext(ctx context.Context) *ZoneGroupsGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the zone groups get params
func (o *ZoneGroupsGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the zone groups get params
func (o *ZoneGroupsGetParams) WithHTTPClient(client *http.Client) *ZoneGroupsGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the zone groups get params
func (o *ZoneGroupsGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the zone groups get params
func (o *ZoneGroupsGetParams) WithID(id string) *ZoneGroupsGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the zone groups get params
func (o *ZoneGroupsGetParams) SetID(id string) {
	o.ID = id
}

// WithMaintenanceMode adds the maintenanceMode to the zone groups get params
func (o *ZoneGroupsGetParams) WithMaintenanceMode(maintenanceMode *string) *ZoneGroupsGetParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the zone groups get params
func (o *ZoneGroupsGetParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *ZoneGroupsGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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