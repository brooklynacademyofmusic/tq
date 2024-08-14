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

// NewCrediteeTypesCreateParams creates a new CrediteeTypesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCrediteeTypesCreateParams() *CrediteeTypesCreateParams {
	return &CrediteeTypesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCrediteeTypesCreateParamsWithTimeout creates a new CrediteeTypesCreateParams object
// with the ability to set a timeout on a request.
func NewCrediteeTypesCreateParamsWithTimeout(timeout time.Duration) *CrediteeTypesCreateParams {
	return &CrediteeTypesCreateParams{
		timeout: timeout,
	}
}

// NewCrediteeTypesCreateParamsWithContext creates a new CrediteeTypesCreateParams object
// with the ability to set a context for a request.
func NewCrediteeTypesCreateParamsWithContext(ctx context.Context) *CrediteeTypesCreateParams {
	return &CrediteeTypesCreateParams{
		Context: ctx,
	}
}

// NewCrediteeTypesCreateParamsWithHTTPClient creates a new CrediteeTypesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewCrediteeTypesCreateParamsWithHTTPClient(client *http.Client) *CrediteeTypesCreateParams {
	return &CrediteeTypesCreateParams{
		HTTPClient: client,
	}
}

/*
CrediteeTypesCreateParams contains all the parameters to send to the API endpoint

	for the creditee types create operation.

	Typically these are written to a http.Request.
*/
type CrediteeTypesCreateParams struct {

	// Data.
	Data *models.CrediteeType

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the creditee types create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CrediteeTypesCreateParams) WithDefaults() *CrediteeTypesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the creditee types create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CrediteeTypesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the creditee types create params
func (o *CrediteeTypesCreateParams) WithTimeout(timeout time.Duration) *CrediteeTypesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the creditee types create params
func (o *CrediteeTypesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the creditee types create params
func (o *CrediteeTypesCreateParams) WithContext(ctx context.Context) *CrediteeTypesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the creditee types create params
func (o *CrediteeTypesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the creditee types create params
func (o *CrediteeTypesCreateParams) WithHTTPClient(client *http.Client) *CrediteeTypesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the creditee types create params
func (o *CrediteeTypesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the creditee types create params
func (o *CrediteeTypesCreateParams) WithData(data *models.CrediteeType) *CrediteeTypesCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the creditee types create params
func (o *CrediteeTypesCreateParams) SetData(data *models.CrediteeType) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *CrediteeTypesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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