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

// NewSeasonsUpdateParams creates a new SeasonsUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSeasonsUpdateParams() *SeasonsUpdateParams {
	return &SeasonsUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSeasonsUpdateParamsWithTimeout creates a new SeasonsUpdateParams object
// with the ability to set a timeout on a request.
func NewSeasonsUpdateParamsWithTimeout(timeout time.Duration) *SeasonsUpdateParams {
	return &SeasonsUpdateParams{
		timeout: timeout,
	}
}

// NewSeasonsUpdateParamsWithContext creates a new SeasonsUpdateParams object
// with the ability to set a context for a request.
func NewSeasonsUpdateParamsWithContext(ctx context.Context) *SeasonsUpdateParams {
	return &SeasonsUpdateParams{
		Context: ctx,
	}
}

// NewSeasonsUpdateParamsWithHTTPClient creates a new SeasonsUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewSeasonsUpdateParamsWithHTTPClient(client *http.Client) *SeasonsUpdateParams {
	return &SeasonsUpdateParams{
		HTTPClient: client,
	}
}

/*
SeasonsUpdateParams contains all the parameters to send to the API endpoint

	for the seasons update operation.

	Typically these are written to a http.Request.
*/
type SeasonsUpdateParams struct {

	// Data.
	Data *models.Season

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the seasons update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SeasonsUpdateParams) WithDefaults() *SeasonsUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the seasons update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SeasonsUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the seasons update params
func (o *SeasonsUpdateParams) WithTimeout(timeout time.Duration) *SeasonsUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the seasons update params
func (o *SeasonsUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the seasons update params
func (o *SeasonsUpdateParams) WithContext(ctx context.Context) *SeasonsUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the seasons update params
func (o *SeasonsUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the seasons update params
func (o *SeasonsUpdateParams) WithHTTPClient(client *http.Client) *SeasonsUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the seasons update params
func (o *SeasonsUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the seasons update params
func (o *SeasonsUpdateParams) WithData(data *models.Season) *SeasonsUpdateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the seasons update params
func (o *SeasonsUpdateParams) SetData(data *models.Season) {
	o.Data = data
}

// WithID adds the id to the seasons update params
func (o *SeasonsUpdateParams) WithID(id string) *SeasonsUpdateParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the seasons update params
func (o *SeasonsUpdateParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *SeasonsUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Data != nil {
		if err := r.SetBodyParam(o.Data); err != nil {
			return err
		}
	}

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}