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

// NewTemplatePricesGetParams creates a new TemplatePricesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewTemplatePricesGetParams() *TemplatePricesGetParams {
	return &TemplatePricesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewTemplatePricesGetParamsWithTimeout creates a new TemplatePricesGetParams object
// with the ability to set a timeout on a request.
func NewTemplatePricesGetParamsWithTimeout(timeout time.Duration) *TemplatePricesGetParams {
	return &TemplatePricesGetParams{
		timeout: timeout,
	}
}

// NewTemplatePricesGetParamsWithContext creates a new TemplatePricesGetParams object
// with the ability to set a context for a request.
func NewTemplatePricesGetParamsWithContext(ctx context.Context) *TemplatePricesGetParams {
	return &TemplatePricesGetParams{
		Context: ctx,
	}
}

// NewTemplatePricesGetParamsWithHTTPClient creates a new TemplatePricesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewTemplatePricesGetParamsWithHTTPClient(client *http.Client) *TemplatePricesGetParams {
	return &TemplatePricesGetParams{
		HTTPClient: client,
	}
}

/*
TemplatePricesGetParams contains all the parameters to send to the API endpoint

	for the template prices get operation.

	Typically these are written to a http.Request.
*/
type TemplatePricesGetParams struct {

	// TemplatePriceID.
	TemplatePriceID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the template prices get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TemplatePricesGetParams) WithDefaults() *TemplatePricesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the template prices get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *TemplatePricesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the template prices get params
func (o *TemplatePricesGetParams) WithTimeout(timeout time.Duration) *TemplatePricesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the template prices get params
func (o *TemplatePricesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the template prices get params
func (o *TemplatePricesGetParams) WithContext(ctx context.Context) *TemplatePricesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the template prices get params
func (o *TemplatePricesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the template prices get params
func (o *TemplatePricesGetParams) WithHTTPClient(client *http.Client) *TemplatePricesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the template prices get params
func (o *TemplatePricesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithTemplatePriceID adds the templatePriceID to the template prices get params
func (o *TemplatePricesGetParams) WithTemplatePriceID(templatePriceID string) *TemplatePricesGetParams {
	o.SetTemplatePriceID(templatePriceID)
	return o
}

// SetTemplatePriceID adds the templatePriceId to the template prices get params
func (o *TemplatePricesGetParams) SetTemplatePriceID(templatePriceID string) {
	o.TemplatePriceID = templatePriceID
}

// WriteToRequest writes these params to a swagger request
func (o *TemplatePricesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param templatePriceId
	if err := r.SetPathParam("templatePriceId", o.TemplatePriceID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}