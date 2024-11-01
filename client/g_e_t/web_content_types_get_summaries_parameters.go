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

// NewWebContentTypesGetSummariesParams creates a new WebContentTypesGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewWebContentTypesGetSummariesParams() *WebContentTypesGetSummariesParams {
	return &WebContentTypesGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewWebContentTypesGetSummariesParamsWithTimeout creates a new WebContentTypesGetSummariesParams object
// with the ability to set a timeout on a request.
func NewWebContentTypesGetSummariesParamsWithTimeout(timeout time.Duration) *WebContentTypesGetSummariesParams {
	return &WebContentTypesGetSummariesParams{
		timeout: timeout,
	}
}

// NewWebContentTypesGetSummariesParamsWithContext creates a new WebContentTypesGetSummariesParams object
// with the ability to set a context for a request.
func NewWebContentTypesGetSummariesParamsWithContext(ctx context.Context) *WebContentTypesGetSummariesParams {
	return &WebContentTypesGetSummariesParams{
		Context: ctx,
	}
}

// NewWebContentTypesGetSummariesParamsWithHTTPClient creates a new WebContentTypesGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewWebContentTypesGetSummariesParamsWithHTTPClient(client *http.Client) *WebContentTypesGetSummariesParams {
	return &WebContentTypesGetSummariesParams{
		HTTPClient: client,
	}
}

/*
WebContentTypesGetSummariesParams contains all the parameters to send to the API endpoint

	for the web content types get summaries operation.

	Typically these are written to a http.Request.
*/
type WebContentTypesGetSummariesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the web content types get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *WebContentTypesGetSummariesParams) WithDefaults() *WebContentTypesGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the web content types get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *WebContentTypesGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the web content types get summaries params
func (o *WebContentTypesGetSummariesParams) WithTimeout(timeout time.Duration) *WebContentTypesGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the web content types get summaries params
func (o *WebContentTypesGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the web content types get summaries params
func (o *WebContentTypesGetSummariesParams) WithContext(ctx context.Context) *WebContentTypesGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the web content types get summaries params
func (o *WebContentTypesGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the web content types get summaries params
func (o *WebContentTypesGetSummariesParams) WithHTTPClient(client *http.Client) *WebContentTypesGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the web content types get summaries params
func (o *WebContentTypesGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *WebContentTypesGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}