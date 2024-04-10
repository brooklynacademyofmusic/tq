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

// NewProgramListingsDeleteParams creates a new ProgramListingsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewProgramListingsDeleteParams() *ProgramListingsDeleteParams {
	return &ProgramListingsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewProgramListingsDeleteParamsWithTimeout creates a new ProgramListingsDeleteParams object
// with the ability to set a timeout on a request.
func NewProgramListingsDeleteParamsWithTimeout(timeout time.Duration) *ProgramListingsDeleteParams {
	return &ProgramListingsDeleteParams{
		timeout: timeout,
	}
}

// NewProgramListingsDeleteParamsWithContext creates a new ProgramListingsDeleteParams object
// with the ability to set a context for a request.
func NewProgramListingsDeleteParamsWithContext(ctx context.Context) *ProgramListingsDeleteParams {
	return &ProgramListingsDeleteParams{
		Context: ctx,
	}
}

// NewProgramListingsDeleteParamsWithHTTPClient creates a new ProgramListingsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewProgramListingsDeleteParamsWithHTTPClient(client *http.Client) *ProgramListingsDeleteParams {
	return &ProgramListingsDeleteParams{
		HTTPClient: client,
	}
}

/*
ProgramListingsDeleteParams contains all the parameters to send to the API endpoint

	for the program listings delete operation.

	Typically these are written to a http.Request.
*/
type ProgramListingsDeleteParams struct {

	// ProgramListingID.
	ProgramListingID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the program listings delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ProgramListingsDeleteParams) WithDefaults() *ProgramListingsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the program listings delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ProgramListingsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the program listings delete params
func (o *ProgramListingsDeleteParams) WithTimeout(timeout time.Duration) *ProgramListingsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the program listings delete params
func (o *ProgramListingsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the program listings delete params
func (o *ProgramListingsDeleteParams) WithContext(ctx context.Context) *ProgramListingsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the program listings delete params
func (o *ProgramListingsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the program listings delete params
func (o *ProgramListingsDeleteParams) WithHTTPClient(client *http.Client) *ProgramListingsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the program listings delete params
func (o *ProgramListingsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithProgramListingID adds the programListingID to the program listings delete params
func (o *ProgramListingsDeleteParams) WithProgramListingID(programListingID string) *ProgramListingsDeleteParams {
	o.SetProgramListingID(programListingID)
	return o
}

// SetProgramListingID adds the programListingId to the program listings delete params
func (o *ProgramListingsDeleteParams) SetProgramListingID(programListingID string) {
	o.ProgramListingID = programListingID
}

// WriteToRequest writes these params to a swagger request
func (o *ProgramListingsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param programListingId
	if err := r.SetPathParam("programListingId", o.ProgramListingID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}