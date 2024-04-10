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

// NewServiceResourceUserGroupsGetParams creates a new ServiceResourceUserGroupsGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewServiceResourceUserGroupsGetParams() *ServiceResourceUserGroupsGetParams {
	return &ServiceResourceUserGroupsGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewServiceResourceUserGroupsGetParamsWithTimeout creates a new ServiceResourceUserGroupsGetParams object
// with the ability to set a timeout on a request.
func NewServiceResourceUserGroupsGetParamsWithTimeout(timeout time.Duration) *ServiceResourceUserGroupsGetParams {
	return &ServiceResourceUserGroupsGetParams{
		timeout: timeout,
	}
}

// NewServiceResourceUserGroupsGetParamsWithContext creates a new ServiceResourceUserGroupsGetParams object
// with the ability to set a context for a request.
func NewServiceResourceUserGroupsGetParamsWithContext(ctx context.Context) *ServiceResourceUserGroupsGetParams {
	return &ServiceResourceUserGroupsGetParams{
		Context: ctx,
	}
}

// NewServiceResourceUserGroupsGetParamsWithHTTPClient creates a new ServiceResourceUserGroupsGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewServiceResourceUserGroupsGetParamsWithHTTPClient(client *http.Client) *ServiceResourceUserGroupsGetParams {
	return &ServiceResourceUserGroupsGetParams{
		HTTPClient: client,
	}
}

/*
ServiceResourceUserGroupsGetParams contains all the parameters to send to the API endpoint

	for the service resource user groups get operation.

	Typically these are written to a http.Request.
*/
type ServiceResourceUserGroupsGetParams struct {

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the service resource user groups get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ServiceResourceUserGroupsGetParams) WithDefaults() *ServiceResourceUserGroupsGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the service resource user groups get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ServiceResourceUserGroupsGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) WithTimeout(timeout time.Duration) *ServiceResourceUserGroupsGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) WithContext(ctx context.Context) *ServiceResourceUserGroupsGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) WithHTTPClient(client *http.Client) *ServiceResourceUserGroupsGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) WithID(id string) *ServiceResourceUserGroupsGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the service resource user groups get params
func (o *ServiceResourceUserGroupsGetParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ServiceResourceUserGroupsGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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