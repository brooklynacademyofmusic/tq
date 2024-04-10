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

// NewConstituentsGetHeaderParams creates a new ConstituentsGetHeaderParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentsGetHeaderParams() *ConstituentsGetHeaderParams {
	return &ConstituentsGetHeaderParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentsGetHeaderParamsWithTimeout creates a new ConstituentsGetHeaderParams object
// with the ability to set a timeout on a request.
func NewConstituentsGetHeaderParamsWithTimeout(timeout time.Duration) *ConstituentsGetHeaderParams {
	return &ConstituentsGetHeaderParams{
		timeout: timeout,
	}
}

// NewConstituentsGetHeaderParamsWithContext creates a new ConstituentsGetHeaderParams object
// with the ability to set a context for a request.
func NewConstituentsGetHeaderParamsWithContext(ctx context.Context) *ConstituentsGetHeaderParams {
	return &ConstituentsGetHeaderParams{
		Context: ctx,
	}
}

// NewConstituentsGetHeaderParamsWithHTTPClient creates a new ConstituentsGetHeaderParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentsGetHeaderParamsWithHTTPClient(client *http.Client) *ConstituentsGetHeaderParams {
	return &ConstituentsGetHeaderParams{
		HTTPClient: client,
	}
}

/*
ConstituentsGetHeaderParams contains all the parameters to send to the API endpoint

	for the constituents get header operation.

	Typically these are written to a http.Request.
*/
type ConstituentsGetHeaderParams struct {

	// ConstituentID.
	ConstituentID string

	// HeaderID.
	HeaderID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituents get header params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsGetHeaderParams) WithDefaults() *ConstituentsGetHeaderParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituents get header params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsGetHeaderParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituents get header params
func (o *ConstituentsGetHeaderParams) WithTimeout(timeout time.Duration) *ConstituentsGetHeaderParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituents get header params
func (o *ConstituentsGetHeaderParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituents get header params
func (o *ConstituentsGetHeaderParams) WithContext(ctx context.Context) *ConstituentsGetHeaderParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituents get header params
func (o *ConstituentsGetHeaderParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituents get header params
func (o *ConstituentsGetHeaderParams) WithHTTPClient(client *http.Client) *ConstituentsGetHeaderParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituents get header params
func (o *ConstituentsGetHeaderParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConstituentID adds the constituentID to the constituents get header params
func (o *ConstituentsGetHeaderParams) WithConstituentID(constituentID string) *ConstituentsGetHeaderParams {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the constituents get header params
func (o *ConstituentsGetHeaderParams) SetConstituentID(constituentID string) {
	o.ConstituentID = constituentID
}

// WithHeaderID adds the headerID to the constituents get header params
func (o *ConstituentsGetHeaderParams) WithHeaderID(headerID string) *ConstituentsGetHeaderParams {
	o.SetHeaderID(headerID)
	return o
}

// SetHeaderID adds the headerId to the constituents get header params
func (o *ConstituentsGetHeaderParams) SetHeaderID(headerID string) {
	o.HeaderID = headerID
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentsGetHeaderParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param constituentId
	if err := r.SetPathParam("constituentId", o.ConstituentID); err != nil {
		return err
	}

	// path param headerId
	if err := r.SetPathParam("headerId", o.HeaderID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}