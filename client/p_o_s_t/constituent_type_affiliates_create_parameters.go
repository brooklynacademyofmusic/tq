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

// NewConstituentTypeAffiliatesCreateParams creates a new ConstituentTypeAffiliatesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentTypeAffiliatesCreateParams() *ConstituentTypeAffiliatesCreateParams {
	return &ConstituentTypeAffiliatesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentTypeAffiliatesCreateParamsWithTimeout creates a new ConstituentTypeAffiliatesCreateParams object
// with the ability to set a timeout on a request.
func NewConstituentTypeAffiliatesCreateParamsWithTimeout(timeout time.Duration) *ConstituentTypeAffiliatesCreateParams {
	return &ConstituentTypeAffiliatesCreateParams{
		timeout: timeout,
	}
}

// NewConstituentTypeAffiliatesCreateParamsWithContext creates a new ConstituentTypeAffiliatesCreateParams object
// with the ability to set a context for a request.
func NewConstituentTypeAffiliatesCreateParamsWithContext(ctx context.Context) *ConstituentTypeAffiliatesCreateParams {
	return &ConstituentTypeAffiliatesCreateParams{
		Context: ctx,
	}
}

// NewConstituentTypeAffiliatesCreateParamsWithHTTPClient creates a new ConstituentTypeAffiliatesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentTypeAffiliatesCreateParamsWithHTTPClient(client *http.Client) *ConstituentTypeAffiliatesCreateParams {
	return &ConstituentTypeAffiliatesCreateParams{
		HTTPClient: client,
	}
}

/*
ConstituentTypeAffiliatesCreateParams contains all the parameters to send to the API endpoint

	for the constituent type affiliates create operation.

	Typically these are written to a http.Request.
*/
type ConstituentTypeAffiliatesCreateParams struct {

	// Data.
	Data *models.ConstituentTypeAffiliate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituent type affiliates create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentTypeAffiliatesCreateParams) WithDefaults() *ConstituentTypeAffiliatesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituent type affiliates create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentTypeAffiliatesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) WithTimeout(timeout time.Duration) *ConstituentTypeAffiliatesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) WithContext(ctx context.Context) *ConstituentTypeAffiliatesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) WithHTTPClient(client *http.Client) *ConstituentTypeAffiliatesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) WithData(data *models.ConstituentTypeAffiliate) *ConstituentTypeAffiliatesCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the constituent type affiliates create params
func (o *ConstituentTypeAffiliatesCreateParams) SetData(data *models.ConstituentTypeAffiliate) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentTypeAffiliatesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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