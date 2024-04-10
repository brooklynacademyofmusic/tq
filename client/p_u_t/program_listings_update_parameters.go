// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

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

// NewProgramListingsUpdateParams creates a new ProgramListingsUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewProgramListingsUpdateParams() *ProgramListingsUpdateParams {
	return &ProgramListingsUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewProgramListingsUpdateParamsWithTimeout creates a new ProgramListingsUpdateParams object
// with the ability to set a timeout on a request.
func NewProgramListingsUpdateParamsWithTimeout(timeout time.Duration) *ProgramListingsUpdateParams {
	return &ProgramListingsUpdateParams{
		timeout: timeout,
	}
}

// NewProgramListingsUpdateParamsWithContext creates a new ProgramListingsUpdateParams object
// with the ability to set a context for a request.
func NewProgramListingsUpdateParamsWithContext(ctx context.Context) *ProgramListingsUpdateParams {
	return &ProgramListingsUpdateParams{
		Context: ctx,
	}
}

// NewProgramListingsUpdateParamsWithHTTPClient creates a new ProgramListingsUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewProgramListingsUpdateParamsWithHTTPClient(client *http.Client) *ProgramListingsUpdateParams {
	return &ProgramListingsUpdateParams{
		HTTPClient: client,
	}
}

/*
ProgramListingsUpdateParams contains all the parameters to send to the API endpoint

	for the program listings update operation.

	Typically these are written to a http.Request.
*/
type ProgramListingsUpdateParams struct {

	// ProgramListing.
	ProgramListing *models.ProgramListing

	// ProgramListingID.
	ProgramListingID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the program listings update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ProgramListingsUpdateParams) WithDefaults() *ProgramListingsUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the program listings update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ProgramListingsUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the program listings update params
func (o *ProgramListingsUpdateParams) WithTimeout(timeout time.Duration) *ProgramListingsUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the program listings update params
func (o *ProgramListingsUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the program listings update params
func (o *ProgramListingsUpdateParams) WithContext(ctx context.Context) *ProgramListingsUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the program listings update params
func (o *ProgramListingsUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the program listings update params
func (o *ProgramListingsUpdateParams) WithHTTPClient(client *http.Client) *ProgramListingsUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the program listings update params
func (o *ProgramListingsUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithProgramListing adds the programListing to the program listings update params
func (o *ProgramListingsUpdateParams) WithProgramListing(programListing *models.ProgramListing) *ProgramListingsUpdateParams {
	o.SetProgramListing(programListing)
	return o
}

// SetProgramListing adds the programListing to the program listings update params
func (o *ProgramListingsUpdateParams) SetProgramListing(programListing *models.ProgramListing) {
	o.ProgramListing = programListing
}

// WithProgramListingID adds the programListingID to the program listings update params
func (o *ProgramListingsUpdateParams) WithProgramListingID(programListingID string) *ProgramListingsUpdateParams {
	o.SetProgramListingID(programListingID)
	return o
}

// SetProgramListingID adds the programListingId to the program listings update params
func (o *ProgramListingsUpdateParams) SetProgramListingID(programListingID string) {
	o.ProgramListingID = programListingID
}

// WriteToRequest writes these params to a swagger request
func (o *ProgramListingsUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ProgramListing != nil {
		if err := r.SetBodyParam(o.ProgramListing); err != nil {
			return err
		}
	}

	// path param programListingId
	if err := r.SetPathParam("programListingId", o.ProgramListingID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}