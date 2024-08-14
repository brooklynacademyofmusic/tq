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

// NewZonesGetParams creates a new ZonesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewZonesGetParams() *ZonesGetParams {
	return &ZonesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewZonesGetParamsWithTimeout creates a new ZonesGetParams object
// with the ability to set a timeout on a request.
func NewZonesGetParamsWithTimeout(timeout time.Duration) *ZonesGetParams {
	return &ZonesGetParams{
		timeout: timeout,
	}
}

// NewZonesGetParamsWithContext creates a new ZonesGetParams object
// with the ability to set a context for a request.
func NewZonesGetParamsWithContext(ctx context.Context) *ZonesGetParams {
	return &ZonesGetParams{
		Context: ctx,
	}
}

// NewZonesGetParamsWithHTTPClient creates a new ZonesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewZonesGetParamsWithHTTPClient(client *http.Client) *ZonesGetParams {
	return &ZonesGetParams{
		HTTPClient: client,
	}
}

/*
ZonesGetParams contains all the parameters to send to the API endpoint

	for the zones get operation.

	Typically these are written to a http.Request.
*/
type ZonesGetParams struct {

	// ZoneID.
	ZoneID string

	// ZoneMapID.
	ZoneMapID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the zones get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ZonesGetParams) WithDefaults() *ZonesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the zones get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ZonesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the zones get params
func (o *ZonesGetParams) WithTimeout(timeout time.Duration) *ZonesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the zones get params
func (o *ZonesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the zones get params
func (o *ZonesGetParams) WithContext(ctx context.Context) *ZonesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the zones get params
func (o *ZonesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the zones get params
func (o *ZonesGetParams) WithHTTPClient(client *http.Client) *ZonesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the zones get params
func (o *ZonesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithZoneID adds the zoneID to the zones get params
func (o *ZonesGetParams) WithZoneID(zoneID string) *ZonesGetParams {
	o.SetZoneID(zoneID)
	return o
}

// SetZoneID adds the zoneId to the zones get params
func (o *ZonesGetParams) SetZoneID(zoneID string) {
	o.ZoneID = zoneID
}

// WithZoneMapID adds the zoneMapID to the zones get params
func (o *ZonesGetParams) WithZoneMapID(zoneMapID string) *ZonesGetParams {
	o.SetZoneMapID(zoneMapID)
	return o
}

// SetZoneMapID adds the zoneMapId to the zones get params
func (o *ZonesGetParams) SetZoneMapID(zoneMapID string) {
	o.ZoneMapID = zoneMapID
}

// WriteToRequest writes these params to a swagger request
func (o *ZonesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param zoneId
	if err := r.SetPathParam("zoneId", o.ZoneID); err != nil {
		return err
	}

	// path param zoneMapId
	if err := r.SetPathParam("zoneMapId", o.ZoneMapID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}