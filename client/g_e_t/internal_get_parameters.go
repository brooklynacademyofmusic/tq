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

// NewInternalGetParams creates a new InternalGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewInternalGetParams() *InternalGetParams {
	return &InternalGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewInternalGetParamsWithTimeout creates a new InternalGetParams object
// with the ability to set a timeout on a request.
func NewInternalGetParamsWithTimeout(timeout time.Duration) *InternalGetParams {
	return &InternalGetParams{
		timeout: timeout,
	}
}

// NewInternalGetParamsWithContext creates a new InternalGetParams object
// with the ability to set a context for a request.
func NewInternalGetParamsWithContext(ctx context.Context) *InternalGetParams {
	return &InternalGetParams{
		Context: ctx,
	}
}

// NewInternalGetParamsWithHTTPClient creates a new InternalGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewInternalGetParamsWithHTTPClient(client *http.Client) *InternalGetParams {
	return &InternalGetParams{
		HTTPClient: client,
	}
}

/*
InternalGetParams contains all the parameters to send to the API endpoint

	for the internal get operation.

	Typically these are written to a http.Request.
*/
type InternalGetParams struct {

	// AddressID.
	AddressID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the internal get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *InternalGetParams) WithDefaults() *InternalGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the internal get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *InternalGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the internal get params
func (o *InternalGetParams) WithTimeout(timeout time.Duration) *InternalGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the internal get params
func (o *InternalGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the internal get params
func (o *InternalGetParams) WithContext(ctx context.Context) *InternalGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the internal get params
func (o *InternalGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the internal get params
func (o *InternalGetParams) WithHTTPClient(client *http.Client) *InternalGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the internal get params
func (o *InternalGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAddressID adds the addressID to the internal get params
func (o *InternalGetParams) WithAddressID(addressID string) *InternalGetParams {
	o.SetAddressID(addressID)
	return o
}

// SetAddressID adds the addressId to the internal get params
func (o *InternalGetParams) SetAddressID(addressID string) {
	o.AddressID = addressID
}

// WriteToRequest writes these params to a swagger request
func (o *InternalGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param addressId
	if err := r.SetPathParam("addressId", o.AddressID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}