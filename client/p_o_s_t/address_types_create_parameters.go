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

// NewAddressTypesCreateParams creates a new AddressTypesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAddressTypesCreateParams() *AddressTypesCreateParams {
	return &AddressTypesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAddressTypesCreateParamsWithTimeout creates a new AddressTypesCreateParams object
// with the ability to set a timeout on a request.
func NewAddressTypesCreateParamsWithTimeout(timeout time.Duration) *AddressTypesCreateParams {
	return &AddressTypesCreateParams{
		timeout: timeout,
	}
}

// NewAddressTypesCreateParamsWithContext creates a new AddressTypesCreateParams object
// with the ability to set a context for a request.
func NewAddressTypesCreateParamsWithContext(ctx context.Context) *AddressTypesCreateParams {
	return &AddressTypesCreateParams{
		Context: ctx,
	}
}

// NewAddressTypesCreateParamsWithHTTPClient creates a new AddressTypesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewAddressTypesCreateParamsWithHTTPClient(client *http.Client) *AddressTypesCreateParams {
	return &AddressTypesCreateParams{
		HTTPClient: client,
	}
}

/*
AddressTypesCreateParams contains all the parameters to send to the API endpoint

	for the address types create operation.

	Typically these are written to a http.Request.
*/
type AddressTypesCreateParams struct {

	// Data.
	Data *models.AddressType

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the address types create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AddressTypesCreateParams) WithDefaults() *AddressTypesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the address types create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AddressTypesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the address types create params
func (o *AddressTypesCreateParams) WithTimeout(timeout time.Duration) *AddressTypesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the address types create params
func (o *AddressTypesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the address types create params
func (o *AddressTypesCreateParams) WithContext(ctx context.Context) *AddressTypesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the address types create params
func (o *AddressTypesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the address types create params
func (o *AddressTypesCreateParams) WithHTTPClient(client *http.Client) *AddressTypesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the address types create params
func (o *AddressTypesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the address types create params
func (o *AddressTypesCreateParams) WithData(data *models.AddressType) *AddressTypesCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the address types create params
func (o *AddressTypesCreateParams) SetData(data *models.AddressType) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *AddressTypesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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