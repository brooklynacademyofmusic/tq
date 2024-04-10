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
)

// NewConstituentsSwapConstituentA1A2Params creates a new ConstituentsSwapConstituentA1A2Params object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentsSwapConstituentA1A2Params() *ConstituentsSwapConstituentA1A2Params {
	return &ConstituentsSwapConstituentA1A2Params{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentsSwapConstituentA1A2ParamsWithTimeout creates a new ConstituentsSwapConstituentA1A2Params object
// with the ability to set a timeout on a request.
func NewConstituentsSwapConstituentA1A2ParamsWithTimeout(timeout time.Duration) *ConstituentsSwapConstituentA1A2Params {
	return &ConstituentsSwapConstituentA1A2Params{
		timeout: timeout,
	}
}

// NewConstituentsSwapConstituentA1A2ParamsWithContext creates a new ConstituentsSwapConstituentA1A2Params object
// with the ability to set a context for a request.
func NewConstituentsSwapConstituentA1A2ParamsWithContext(ctx context.Context) *ConstituentsSwapConstituentA1A2Params {
	return &ConstituentsSwapConstituentA1A2Params{
		Context: ctx,
	}
}

// NewConstituentsSwapConstituentA1A2ParamsWithHTTPClient creates a new ConstituentsSwapConstituentA1A2Params object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentsSwapConstituentA1A2ParamsWithHTTPClient(client *http.Client) *ConstituentsSwapConstituentA1A2Params {
	return &ConstituentsSwapConstituentA1A2Params{
		HTTPClient: client,
	}
}

/*
ConstituentsSwapConstituentA1A2Params contains all the parameters to send to the API endpoint

	for the constituents swap constituent a1 a2 operation.

	Typically these are written to a http.Request.
*/
type ConstituentsSwapConstituentA1A2Params struct {

	// ConstituentID.
	ConstituentID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituents swap constituent a1 a2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsSwapConstituentA1A2Params) WithDefaults() *ConstituentsSwapConstituentA1A2Params {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituents swap constituent a1 a2 params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsSwapConstituentA1A2Params) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) WithTimeout(timeout time.Duration) *ConstituentsSwapConstituentA1A2Params {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) WithContext(ctx context.Context) *ConstituentsSwapConstituentA1A2Params {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) WithHTTPClient(client *http.Client) *ConstituentsSwapConstituentA1A2Params {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConstituentID adds the constituentID to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) WithConstituentID(constituentID string) *ConstituentsSwapConstituentA1A2Params {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the constituents swap constituent a1 a2 params
func (o *ConstituentsSwapConstituentA1A2Params) SetConstituentID(constituentID string) {
	o.ConstituentID = constituentID
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentsSwapConstituentA1A2Params) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param constituentId
	if err := r.SetPathParam("constituentId", o.ConstituentID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}