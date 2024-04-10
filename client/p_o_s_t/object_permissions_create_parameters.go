// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

	"github.com/skysyzygy/tq/models"
)

// NewObjectPermissionsCreateParams creates a new ObjectPermissionsCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewObjectPermissionsCreateParams() *ObjectPermissionsCreateParams {
	return &ObjectPermissionsCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewObjectPermissionsCreateParamsWithTimeout creates a new ObjectPermissionsCreateParams object
// with the ability to set a timeout on a request.
func NewObjectPermissionsCreateParamsWithTimeout(timeout time.Duration) *ObjectPermissionsCreateParams {
	return &ObjectPermissionsCreateParams{
		timeout: timeout,
	}
}

// NewObjectPermissionsCreateParamsWithContext creates a new ObjectPermissionsCreateParams object
// with the ability to set a context for a request.
func NewObjectPermissionsCreateParamsWithContext(ctx context.Context) *ObjectPermissionsCreateParams {
	return &ObjectPermissionsCreateParams{
		Context: ctx,
	}
}

// NewObjectPermissionsCreateParamsWithHTTPClient creates a new ObjectPermissionsCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewObjectPermissionsCreateParamsWithHTTPClient(client *http.Client) *ObjectPermissionsCreateParams {
	return &ObjectPermissionsCreateParams{
		HTTPClient: client,
	}
}

/*
ObjectPermissionsCreateParams contains all the parameters to send to the API endpoint

	for the object permissions create operation.

	Typically these are written to a http.Request.
*/
type ObjectPermissionsCreateParams struct {

	// Data.
	Data *models.ObjectPermission

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the object permissions create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ObjectPermissionsCreateParams) WithDefaults() *ObjectPermissionsCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the object permissions create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ObjectPermissionsCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the object permissions create params
func (o *ObjectPermissionsCreateParams) WithTimeout(timeout time.Duration) *ObjectPermissionsCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the object permissions create params
func (o *ObjectPermissionsCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the object permissions create params
func (o *ObjectPermissionsCreateParams) WithContext(ctx context.Context) *ObjectPermissionsCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the object permissions create params
func (o *ObjectPermissionsCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the object permissions create params
func (o *ObjectPermissionsCreateParams) WithHTTPClient(client *http.Client) *ObjectPermissionsCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the object permissions create params
func (o *ObjectPermissionsCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the object permissions create params
func (o *ObjectPermissionsCreateParams) WithData(data *models.ObjectPermission) *ObjectPermissionsCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the object permissions create params
func (o *ObjectPermissionsCreateParams) SetData(data *models.ObjectPermission) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *ObjectPermissionsCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Data != nil {
		if err := r.SetBodyParam(o.Data); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}