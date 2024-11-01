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

// NewSeasonTypesGetSummariesParams creates a new SeasonTypesGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSeasonTypesGetSummariesParams() *SeasonTypesGetSummariesParams {
	return &SeasonTypesGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSeasonTypesGetSummariesParamsWithTimeout creates a new SeasonTypesGetSummariesParams object
// with the ability to set a timeout on a request.
func NewSeasonTypesGetSummariesParamsWithTimeout(timeout time.Duration) *SeasonTypesGetSummariesParams {
	return &SeasonTypesGetSummariesParams{
		timeout: timeout,
	}
}

// NewSeasonTypesGetSummariesParamsWithContext creates a new SeasonTypesGetSummariesParams object
// with the ability to set a context for a request.
func NewSeasonTypesGetSummariesParamsWithContext(ctx context.Context) *SeasonTypesGetSummariesParams {
	return &SeasonTypesGetSummariesParams{
		Context: ctx,
	}
}

// NewSeasonTypesGetSummariesParamsWithHTTPClient creates a new SeasonTypesGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewSeasonTypesGetSummariesParamsWithHTTPClient(client *http.Client) *SeasonTypesGetSummariesParams {
	return &SeasonTypesGetSummariesParams{
		HTTPClient: client,
	}
}

/*
SeasonTypesGetSummariesParams contains all the parameters to send to the API endpoint

	for the season types get summaries operation.

	Typically these are written to a http.Request.
*/
type SeasonTypesGetSummariesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the season types get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SeasonTypesGetSummariesParams) WithDefaults() *SeasonTypesGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the season types get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SeasonTypesGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the season types get summaries params
func (o *SeasonTypesGetSummariesParams) WithTimeout(timeout time.Duration) *SeasonTypesGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the season types get summaries params
func (o *SeasonTypesGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the season types get summaries params
func (o *SeasonTypesGetSummariesParams) WithContext(ctx context.Context) *SeasonTypesGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the season types get summaries params
func (o *SeasonTypesGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the season types get summaries params
func (o *SeasonTypesGetSummariesParams) WithHTTPClient(client *http.Client) *SeasonTypesGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the season types get summaries params
func (o *SeasonTypesGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *SeasonTypesGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}