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

// NewProgramsCreateParams creates a new ProgramsCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewProgramsCreateParams() *ProgramsCreateParams {
	return &ProgramsCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewProgramsCreateParamsWithTimeout creates a new ProgramsCreateParams object
// with the ability to set a timeout on a request.
func NewProgramsCreateParamsWithTimeout(timeout time.Duration) *ProgramsCreateParams {
	return &ProgramsCreateParams{
		timeout: timeout,
	}
}

// NewProgramsCreateParamsWithContext creates a new ProgramsCreateParams object
// with the ability to set a context for a request.
func NewProgramsCreateParamsWithContext(ctx context.Context) *ProgramsCreateParams {
	return &ProgramsCreateParams{
		Context: ctx,
	}
}

// NewProgramsCreateParamsWithHTTPClient creates a new ProgramsCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewProgramsCreateParamsWithHTTPClient(client *http.Client) *ProgramsCreateParams {
	return &ProgramsCreateParams{
		HTTPClient: client,
	}
}

/*
ProgramsCreateParams contains all the parameters to send to the API endpoint

	for the programs create operation.

	Typically these are written to a http.Request.
*/
type ProgramsCreateParams struct {

	// Data.
	Data *models.Program

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the programs create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ProgramsCreateParams) WithDefaults() *ProgramsCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the programs create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ProgramsCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the programs create params
func (o *ProgramsCreateParams) WithTimeout(timeout time.Duration) *ProgramsCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the programs create params
func (o *ProgramsCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the programs create params
func (o *ProgramsCreateParams) WithContext(ctx context.Context) *ProgramsCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the programs create params
func (o *ProgramsCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the programs create params
func (o *ProgramsCreateParams) WithHTTPClient(client *http.Client) *ProgramsCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the programs create params
func (o *ProgramsCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the programs create params
func (o *ProgramsCreateParams) WithData(data *models.Program) *ProgramsCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the programs create params
func (o *ProgramsCreateParams) SetData(data *models.Program) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *ProgramsCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Data != nil {
		if err := r.SetBodyParam(o.Data); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}