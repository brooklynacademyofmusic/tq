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

// NewPriceTypeCategoriesGetSummariesParams creates a new PriceTypeCategoriesGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPriceTypeCategoriesGetSummariesParams() *PriceTypeCategoriesGetSummariesParams {
	return &PriceTypeCategoriesGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPriceTypeCategoriesGetSummariesParamsWithTimeout creates a new PriceTypeCategoriesGetSummariesParams object
// with the ability to set a timeout on a request.
func NewPriceTypeCategoriesGetSummariesParamsWithTimeout(timeout time.Duration) *PriceTypeCategoriesGetSummariesParams {
	return &PriceTypeCategoriesGetSummariesParams{
		timeout: timeout,
	}
}

// NewPriceTypeCategoriesGetSummariesParamsWithContext creates a new PriceTypeCategoriesGetSummariesParams object
// with the ability to set a context for a request.
func NewPriceTypeCategoriesGetSummariesParamsWithContext(ctx context.Context) *PriceTypeCategoriesGetSummariesParams {
	return &PriceTypeCategoriesGetSummariesParams{
		Context: ctx,
	}
}

// NewPriceTypeCategoriesGetSummariesParamsWithHTTPClient creates a new PriceTypeCategoriesGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewPriceTypeCategoriesGetSummariesParamsWithHTTPClient(client *http.Client) *PriceTypeCategoriesGetSummariesParams {
	return &PriceTypeCategoriesGetSummariesParams{
		HTTPClient: client,
	}
}

/*
PriceTypeCategoriesGetSummariesParams contains all the parameters to send to the API endpoint

	for the price type categories get summaries operation.

	Typically these are written to a http.Request.
*/
type PriceTypeCategoriesGetSummariesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the price type categories get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceTypeCategoriesGetSummariesParams) WithDefaults() *PriceTypeCategoriesGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the price type categories get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceTypeCategoriesGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the price type categories get summaries params
func (o *PriceTypeCategoriesGetSummariesParams) WithTimeout(timeout time.Duration) *PriceTypeCategoriesGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the price type categories get summaries params
func (o *PriceTypeCategoriesGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the price type categories get summaries params
func (o *PriceTypeCategoriesGetSummariesParams) WithContext(ctx context.Context) *PriceTypeCategoriesGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the price type categories get summaries params
func (o *PriceTypeCategoriesGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the price type categories get summaries params
func (o *PriceTypeCategoriesGetSummariesParams) WithHTTPClient(client *http.Client) *PriceTypeCategoriesGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the price type categories get summaries params
func (o *PriceTypeCategoriesGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *PriceTypeCategoriesGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}