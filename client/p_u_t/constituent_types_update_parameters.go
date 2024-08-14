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

// NewConstituentTypesUpdateParams creates a new ConstituentTypesUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentTypesUpdateParams() *ConstituentTypesUpdateParams {
	return &ConstituentTypesUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentTypesUpdateParamsWithTimeout creates a new ConstituentTypesUpdateParams object
// with the ability to set a timeout on a request.
func NewConstituentTypesUpdateParamsWithTimeout(timeout time.Duration) *ConstituentTypesUpdateParams {
	return &ConstituentTypesUpdateParams{
		timeout: timeout,
	}
}

// NewConstituentTypesUpdateParamsWithContext creates a new ConstituentTypesUpdateParams object
// with the ability to set a context for a request.
func NewConstituentTypesUpdateParamsWithContext(ctx context.Context) *ConstituentTypesUpdateParams {
	return &ConstituentTypesUpdateParams{
		Context: ctx,
	}
}

// NewConstituentTypesUpdateParamsWithHTTPClient creates a new ConstituentTypesUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentTypesUpdateParamsWithHTTPClient(client *http.Client) *ConstituentTypesUpdateParams {
	return &ConstituentTypesUpdateParams{
		HTTPClient: client,
	}
}

/*
ConstituentTypesUpdateParams contains all the parameters to send to the API endpoint

	for the constituent types update operation.

	Typically these are written to a http.Request.
*/
type ConstituentTypesUpdateParams struct {

	// Data.
	Data *models.ConstituentType

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituent types update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentTypesUpdateParams) WithDefaults() *ConstituentTypesUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituent types update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentTypesUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituent types update params
func (o *ConstituentTypesUpdateParams) WithTimeout(timeout time.Duration) *ConstituentTypesUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituent types update params
func (o *ConstituentTypesUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituent types update params
func (o *ConstituentTypesUpdateParams) WithContext(ctx context.Context) *ConstituentTypesUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituent types update params
func (o *ConstituentTypesUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituent types update params
func (o *ConstituentTypesUpdateParams) WithHTTPClient(client *http.Client) *ConstituentTypesUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituent types update params
func (o *ConstituentTypesUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the constituent types update params
func (o *ConstituentTypesUpdateParams) WithData(data *models.ConstituentType) *ConstituentTypesUpdateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the constituent types update params
func (o *ConstituentTypesUpdateParams) SetData(data *models.ConstituentType) {
	o.Data = data
}

// WithID adds the id to the constituent types update params
func (o *ConstituentTypesUpdateParams) WithID(id string) *ConstituentTypesUpdateParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the constituent types update params
func (o *ConstituentTypesUpdateParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentTypesUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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