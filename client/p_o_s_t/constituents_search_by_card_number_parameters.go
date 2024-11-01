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

// NewConstituentsSearchByCardNumberParams creates a new ConstituentsSearchByCardNumberParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentsSearchByCardNumberParams() *ConstituentsSearchByCardNumberParams {
	return &ConstituentsSearchByCardNumberParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentsSearchByCardNumberParamsWithTimeout creates a new ConstituentsSearchByCardNumberParams object
// with the ability to set a timeout on a request.
func NewConstituentsSearchByCardNumberParamsWithTimeout(timeout time.Duration) *ConstituentsSearchByCardNumberParams {
	return &ConstituentsSearchByCardNumberParams{
		timeout: timeout,
	}
}

// NewConstituentsSearchByCardNumberParamsWithContext creates a new ConstituentsSearchByCardNumberParams object
// with the ability to set a context for a request.
func NewConstituentsSearchByCardNumberParamsWithContext(ctx context.Context) *ConstituentsSearchByCardNumberParams {
	return &ConstituentsSearchByCardNumberParams{
		Context: ctx,
	}
}

// NewConstituentsSearchByCardNumberParamsWithHTTPClient creates a new ConstituentsSearchByCardNumberParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentsSearchByCardNumberParamsWithHTTPClient(client *http.Client) *ConstituentsSearchByCardNumberParams {
	return &ConstituentsSearchByCardNumberParams{
		HTTPClient: client,
	}
}

/*
ConstituentsSearchByCardNumberParams contains all the parameters to send to the API endpoint

	for the constituents search by card number operation.

	Typically these are written to a http.Request.
*/
type ConstituentsSearchByCardNumberParams struct {

	// SearchRequest.
	SearchRequest *models.SearchRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituents search by card number params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsSearchByCardNumberParams) WithDefaults() *ConstituentsSearchByCardNumberParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituents search by card number params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsSearchByCardNumberParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) WithTimeout(timeout time.Duration) *ConstituentsSearchByCardNumberParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) WithContext(ctx context.Context) *ConstituentsSearchByCardNumberParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) WithHTTPClient(client *http.Client) *ConstituentsSearchByCardNumberParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSearchRequest adds the searchRequest to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) WithSearchRequest(searchRequest *models.SearchRequest) *ConstituentsSearchByCardNumberParams {
	o.SetSearchRequest(searchRequest)
	return o
}

// SetSearchRequest adds the searchRequest to the constituents search by card number params
func (o *ConstituentsSearchByCardNumberParams) SetSearchRequest(searchRequest *models.SearchRequest) {
	o.SearchRequest = searchRequest
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentsSearchByCardNumberParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.SearchRequest != nil {
		if err := r.SetBodyParam(o.SearchRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}