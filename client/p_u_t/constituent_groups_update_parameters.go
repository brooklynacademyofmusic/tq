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

// NewConstituentGroupsUpdateParams creates a new ConstituentGroupsUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentGroupsUpdateParams() *ConstituentGroupsUpdateParams {
	return &ConstituentGroupsUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentGroupsUpdateParamsWithTimeout creates a new ConstituentGroupsUpdateParams object
// with the ability to set a timeout on a request.
func NewConstituentGroupsUpdateParamsWithTimeout(timeout time.Duration) *ConstituentGroupsUpdateParams {
	return &ConstituentGroupsUpdateParams{
		timeout: timeout,
	}
}

// NewConstituentGroupsUpdateParamsWithContext creates a new ConstituentGroupsUpdateParams object
// with the ability to set a context for a request.
func NewConstituentGroupsUpdateParamsWithContext(ctx context.Context) *ConstituentGroupsUpdateParams {
	return &ConstituentGroupsUpdateParams{
		Context: ctx,
	}
}

// NewConstituentGroupsUpdateParamsWithHTTPClient creates a new ConstituentGroupsUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentGroupsUpdateParamsWithHTTPClient(client *http.Client) *ConstituentGroupsUpdateParams {
	return &ConstituentGroupsUpdateParams{
		HTTPClient: client,
	}
}

/*
ConstituentGroupsUpdateParams contains all the parameters to send to the API endpoint

	for the constituent groups update operation.

	Typically these are written to a http.Request.
*/
type ConstituentGroupsUpdateParams struct {

	// Data.
	Data *models.ConstituentGroup

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituent groups update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentGroupsUpdateParams) WithDefaults() *ConstituentGroupsUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituent groups update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentGroupsUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) WithTimeout(timeout time.Duration) *ConstituentGroupsUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) WithContext(ctx context.Context) *ConstituentGroupsUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) WithHTTPClient(client *http.Client) *ConstituentGroupsUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) WithData(data *models.ConstituentGroup) *ConstituentGroupsUpdateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) SetData(data *models.ConstituentGroup) {
	o.Data = data
}

// WithID adds the id to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) WithID(id string) *ConstituentGroupsUpdateParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the constituent groups update params
func (o *ConstituentGroupsUpdateParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentGroupsUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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