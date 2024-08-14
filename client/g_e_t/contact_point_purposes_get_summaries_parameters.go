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

// NewContactPointPurposesGetSummariesParams creates a new ContactPointPurposesGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewContactPointPurposesGetSummariesParams() *ContactPointPurposesGetSummariesParams {
	return &ContactPointPurposesGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewContactPointPurposesGetSummariesParamsWithTimeout creates a new ContactPointPurposesGetSummariesParams object
// with the ability to set a timeout on a request.
func NewContactPointPurposesGetSummariesParamsWithTimeout(timeout time.Duration) *ContactPointPurposesGetSummariesParams {
	return &ContactPointPurposesGetSummariesParams{
		timeout: timeout,
	}
}

// NewContactPointPurposesGetSummariesParamsWithContext creates a new ContactPointPurposesGetSummariesParams object
// with the ability to set a context for a request.
func NewContactPointPurposesGetSummariesParamsWithContext(ctx context.Context) *ContactPointPurposesGetSummariesParams {
	return &ContactPointPurposesGetSummariesParams{
		Context: ctx,
	}
}

// NewContactPointPurposesGetSummariesParamsWithHTTPClient creates a new ContactPointPurposesGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewContactPointPurposesGetSummariesParamsWithHTTPClient(client *http.Client) *ContactPointPurposesGetSummariesParams {
	return &ContactPointPurposesGetSummariesParams{
		HTTPClient: client,
	}
}

/*
ContactPointPurposesGetSummariesParams contains all the parameters to send to the API endpoint

	for the contact point purposes get summaries operation.

	Typically these are written to a http.Request.
*/
type ContactPointPurposesGetSummariesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the contact point purposes get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContactPointPurposesGetSummariesParams) WithDefaults() *ContactPointPurposesGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the contact point purposes get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ContactPointPurposesGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the contact point purposes get summaries params
func (o *ContactPointPurposesGetSummariesParams) WithTimeout(timeout time.Duration) *ContactPointPurposesGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the contact point purposes get summaries params
func (o *ContactPointPurposesGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the contact point purposes get summaries params
func (o *ContactPointPurposesGetSummariesParams) WithContext(ctx context.Context) *ContactPointPurposesGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the contact point purposes get summaries params
func (o *ContactPointPurposesGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the contact point purposes get summaries params
func (o *ContactPointPurposesGetSummariesParams) WithHTTPClient(client *http.Client) *ContactPointPurposesGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the contact point purposes get summaries params
func (o *ContactPointPurposesGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *ContactPointPurposesGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}