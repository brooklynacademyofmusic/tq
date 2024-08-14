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

// NewColorsGetSummariesParams creates a new ColorsGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewColorsGetSummariesParams() *ColorsGetSummariesParams {
	return &ColorsGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewColorsGetSummariesParamsWithTimeout creates a new ColorsGetSummariesParams object
// with the ability to set a timeout on a request.
func NewColorsGetSummariesParamsWithTimeout(timeout time.Duration) *ColorsGetSummariesParams {
	return &ColorsGetSummariesParams{
		timeout: timeout,
	}
}

// NewColorsGetSummariesParamsWithContext creates a new ColorsGetSummariesParams object
// with the ability to set a context for a request.
func NewColorsGetSummariesParamsWithContext(ctx context.Context) *ColorsGetSummariesParams {
	return &ColorsGetSummariesParams{
		Context: ctx,
	}
}

// NewColorsGetSummariesParamsWithHTTPClient creates a new ColorsGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewColorsGetSummariesParamsWithHTTPClient(client *http.Client) *ColorsGetSummariesParams {
	return &ColorsGetSummariesParams{
		HTTPClient: client,
	}
}

/*
ColorsGetSummariesParams contains all the parameters to send to the API endpoint

	for the colors get summaries operation.

	Typically these are written to a http.Request.
*/
type ColorsGetSummariesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the colors get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ColorsGetSummariesParams) WithDefaults() *ColorsGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the colors get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ColorsGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the colors get summaries params
func (o *ColorsGetSummariesParams) WithTimeout(timeout time.Duration) *ColorsGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the colors get summaries params
func (o *ColorsGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the colors get summaries params
func (o *ColorsGetSummariesParams) WithContext(ctx context.Context) *ColorsGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the colors get summaries params
func (o *ColorsGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the colors get summaries params
func (o *ColorsGetSummariesParams) WithHTTPClient(client *http.Client) *ColorsGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the colors get summaries params
func (o *ColorsGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ColorsGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}