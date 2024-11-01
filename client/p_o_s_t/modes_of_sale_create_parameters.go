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

// NewModesOfSaleCreateParams creates a new ModesOfSaleCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewModesOfSaleCreateParams() *ModesOfSaleCreateParams {
	return &ModesOfSaleCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewModesOfSaleCreateParamsWithTimeout creates a new ModesOfSaleCreateParams object
// with the ability to set a timeout on a request.
func NewModesOfSaleCreateParamsWithTimeout(timeout time.Duration) *ModesOfSaleCreateParams {
	return &ModesOfSaleCreateParams{
		timeout: timeout,
	}
}

// NewModesOfSaleCreateParamsWithContext creates a new ModesOfSaleCreateParams object
// with the ability to set a context for a request.
func NewModesOfSaleCreateParamsWithContext(ctx context.Context) *ModesOfSaleCreateParams {
	return &ModesOfSaleCreateParams{
		Context: ctx,
	}
}

// NewModesOfSaleCreateParamsWithHTTPClient creates a new ModesOfSaleCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewModesOfSaleCreateParamsWithHTTPClient(client *http.Client) *ModesOfSaleCreateParams {
	return &ModesOfSaleCreateParams{
		HTTPClient: client,
	}
}

/*
ModesOfSaleCreateParams contains all the parameters to send to the API endpoint

	for the modes of sale create operation.

	Typically these are written to a http.Request.
*/
type ModesOfSaleCreateParams struct {

	// ModeOfSale.
	ModeOfSale *models.ModeOfSale

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the modes of sale create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ModesOfSaleCreateParams) WithDefaults() *ModesOfSaleCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the modes of sale create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ModesOfSaleCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the modes of sale create params
func (o *ModesOfSaleCreateParams) WithTimeout(timeout time.Duration) *ModesOfSaleCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the modes of sale create params
func (o *ModesOfSaleCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the modes of sale create params
func (o *ModesOfSaleCreateParams) WithContext(ctx context.Context) *ModesOfSaleCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the modes of sale create params
func (o *ModesOfSaleCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the modes of sale create params
func (o *ModesOfSaleCreateParams) WithHTTPClient(client *http.Client) *ModesOfSaleCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the modes of sale create params
func (o *ModesOfSaleCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithModeOfSale adds the modeOfSale to the modes of sale create params
func (o *ModesOfSaleCreateParams) WithModeOfSale(modeOfSale *models.ModeOfSale) *ModesOfSaleCreateParams {
	o.SetModeOfSale(modeOfSale)
	return o
}

// SetModeOfSale adds the modeOfSale to the modes of sale create params
func (o *ModesOfSaleCreateParams) SetModeOfSale(modeOfSale *models.ModeOfSale) {
	o.ModeOfSale = modeOfSale
}

// WriteToRequest writes these params to a swagger request
func (o *ModesOfSaleCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ModeOfSale != nil {
		if err := r.SetBodyParam(o.ModeOfSale); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}