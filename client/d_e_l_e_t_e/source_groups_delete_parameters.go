// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// NewSourceGroupsDeleteParams creates a new SourceGroupsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSourceGroupsDeleteParams() *SourceGroupsDeleteParams {
	return &SourceGroupsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSourceGroupsDeleteParamsWithTimeout creates a new SourceGroupsDeleteParams object
// with the ability to set a timeout on a request.
func NewSourceGroupsDeleteParamsWithTimeout(timeout time.Duration) *SourceGroupsDeleteParams {
	return &SourceGroupsDeleteParams{
		timeout: timeout,
	}
}

// NewSourceGroupsDeleteParamsWithContext creates a new SourceGroupsDeleteParams object
// with the ability to set a context for a request.
func NewSourceGroupsDeleteParamsWithContext(ctx context.Context) *SourceGroupsDeleteParams {
	return &SourceGroupsDeleteParams{
		Context: ctx,
	}
}

// NewSourceGroupsDeleteParamsWithHTTPClient creates a new SourceGroupsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewSourceGroupsDeleteParamsWithHTTPClient(client *http.Client) *SourceGroupsDeleteParams {
	return &SourceGroupsDeleteParams{
		HTTPClient: client,
	}
}

/*
SourceGroupsDeleteParams contains all the parameters to send to the API endpoint

	for the source groups delete operation.

	Typically these are written to a http.Request.
*/
type SourceGroupsDeleteParams struct {

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the source groups delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SourceGroupsDeleteParams) WithDefaults() *SourceGroupsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the source groups delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SourceGroupsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the source groups delete params
func (o *SourceGroupsDeleteParams) WithTimeout(timeout time.Duration) *SourceGroupsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the source groups delete params
func (o *SourceGroupsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the source groups delete params
func (o *SourceGroupsDeleteParams) WithContext(ctx context.Context) *SourceGroupsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the source groups delete params
func (o *SourceGroupsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the source groups delete params
func (o *SourceGroupsDeleteParams) WithHTTPClient(client *http.Client) *SourceGroupsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the source groups delete params
func (o *SourceGroupsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the source groups delete params
func (o *SourceGroupsDeleteParams) WithID(id string) *SourceGroupsDeleteParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the source groups delete params
func (o *SourceGroupsDeleteParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *SourceGroupsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}