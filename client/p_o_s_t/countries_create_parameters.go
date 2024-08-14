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

// NewCountriesCreateParams creates a new CountriesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCountriesCreateParams() *CountriesCreateParams {
	return &CountriesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCountriesCreateParamsWithTimeout creates a new CountriesCreateParams object
// with the ability to set a timeout on a request.
func NewCountriesCreateParamsWithTimeout(timeout time.Duration) *CountriesCreateParams {
	return &CountriesCreateParams{
		timeout: timeout,
	}
}

// NewCountriesCreateParamsWithContext creates a new CountriesCreateParams object
// with the ability to set a context for a request.
func NewCountriesCreateParamsWithContext(ctx context.Context) *CountriesCreateParams {
	return &CountriesCreateParams{
		Context: ctx,
	}
}

// NewCountriesCreateParamsWithHTTPClient creates a new CountriesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewCountriesCreateParamsWithHTTPClient(client *http.Client) *CountriesCreateParams {
	return &CountriesCreateParams{
		HTTPClient: client,
	}
}

/*
CountriesCreateParams contains all the parameters to send to the API endpoint

	for the countries create operation.

	Typically these are written to a http.Request.
*/
type CountriesCreateParams struct {

	// Data.
	Data *models.Country

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the countries create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CountriesCreateParams) WithDefaults() *CountriesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the countries create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CountriesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the countries create params
func (o *CountriesCreateParams) WithTimeout(timeout time.Duration) *CountriesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the countries create params
func (o *CountriesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the countries create params
func (o *CountriesCreateParams) WithContext(ctx context.Context) *CountriesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the countries create params
func (o *CountriesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the countries create params
func (o *CountriesCreateParams) WithHTTPClient(client *http.Client) *CountriesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the countries create params
func (o *CountriesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the countries create params
func (o *CountriesCreateParams) WithData(data *models.Country) *CountriesCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the countries create params
func (o *CountriesCreateParams) SetData(data *models.Country) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *CountriesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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