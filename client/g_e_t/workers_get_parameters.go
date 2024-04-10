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

// NewWorkersGetParams creates a new WorkersGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewWorkersGetParams() *WorkersGetParams {
	return &WorkersGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewWorkersGetParamsWithTimeout creates a new WorkersGetParams object
// with the ability to set a timeout on a request.
func NewWorkersGetParamsWithTimeout(timeout time.Duration) *WorkersGetParams {
	return &WorkersGetParams{
		timeout: timeout,
	}
}

// NewWorkersGetParamsWithContext creates a new WorkersGetParams object
// with the ability to set a context for a request.
func NewWorkersGetParamsWithContext(ctx context.Context) *WorkersGetParams {
	return &WorkersGetParams{
		Context: ctx,
	}
}

// NewWorkersGetParamsWithHTTPClient creates a new WorkersGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewWorkersGetParamsWithHTTPClient(client *http.Client) *WorkersGetParams {
	return &WorkersGetParams{
		HTTPClient: client,
	}
}

/*
WorkersGetParams contains all the parameters to send to the API endpoint

	for the workers get operation.

	Typically these are written to a http.Request.
*/
type WorkersGetParams struct {

	// WorkerID.
	WorkerID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the workers get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *WorkersGetParams) WithDefaults() *WorkersGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the workers get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *WorkersGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the workers get params
func (o *WorkersGetParams) WithTimeout(timeout time.Duration) *WorkersGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the workers get params
func (o *WorkersGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the workers get params
func (o *WorkersGetParams) WithContext(ctx context.Context) *WorkersGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the workers get params
func (o *WorkersGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the workers get params
func (o *WorkersGetParams) WithHTTPClient(client *http.Client) *WorkersGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the workers get params
func (o *WorkersGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithWorkerID adds the workerID to the workers get params
func (o *WorkersGetParams) WithWorkerID(workerID string) *WorkersGetParams {
	o.SetWorkerID(workerID)
	return o
}

// SetWorkerID adds the workerId to the workers get params
func (o *WorkersGetParams) SetWorkerID(workerID string) {
	o.WorkerID = workerID
}

// WriteToRequest writes these params to a swagger request
func (o *WorkersGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param workerId
	if err := r.SetPathParam("workerId", o.WorkerID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}