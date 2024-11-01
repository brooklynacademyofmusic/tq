// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// NewPhonesDeleteParams creates a new PhonesDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPhonesDeleteParams() *PhonesDeleteParams {
	return &PhonesDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPhonesDeleteParamsWithTimeout creates a new PhonesDeleteParams object
// with the ability to set a timeout on a request.
func NewPhonesDeleteParamsWithTimeout(timeout time.Duration) *PhonesDeleteParams {
	return &PhonesDeleteParams{
		timeout: timeout,
	}
}

// NewPhonesDeleteParamsWithContext creates a new PhonesDeleteParams object
// with the ability to set a context for a request.
func NewPhonesDeleteParamsWithContext(ctx context.Context) *PhonesDeleteParams {
	return &PhonesDeleteParams{
		Context: ctx,
	}
}

// NewPhonesDeleteParamsWithHTTPClient creates a new PhonesDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewPhonesDeleteParamsWithHTTPClient(client *http.Client) *PhonesDeleteParams {
	return &PhonesDeleteParams{
		HTTPClient: client,
	}
}

/*
PhonesDeleteParams contains all the parameters to send to the API endpoint

	for the phones delete operation.

	Typically these are written to a http.Request.
*/
type PhonesDeleteParams struct {

	// PhoneID.
	PhoneID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the phones delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PhonesDeleteParams) WithDefaults() *PhonesDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the phones delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PhonesDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the phones delete params
func (o *PhonesDeleteParams) WithTimeout(timeout time.Duration) *PhonesDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the phones delete params
func (o *PhonesDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the phones delete params
func (o *PhonesDeleteParams) WithContext(ctx context.Context) *PhonesDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the phones delete params
func (o *PhonesDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the phones delete params
func (o *PhonesDeleteParams) WithHTTPClient(client *http.Client) *PhonesDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the phones delete params
func (o *PhonesDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPhoneID adds the phoneID to the phones delete params
func (o *PhonesDeleteParams) WithPhoneID(phoneID string) *PhonesDeleteParams {
	o.SetPhoneID(phoneID)
	return o
}

// SetPhoneID adds the phoneId to the phones delete params
func (o *PhonesDeleteParams) SetPhoneID(phoneID string) {
	o.PhoneID = phoneID
}

// WriteToRequest writes these params to a swagger request
func (o *PhonesDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param phoneId
	if err := r.SetPathParam("phoneId", o.PhoneID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}