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

// NewCardReaderTypesDeleteParams creates a new CardReaderTypesDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCardReaderTypesDeleteParams() *CardReaderTypesDeleteParams {
	return &CardReaderTypesDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCardReaderTypesDeleteParamsWithTimeout creates a new CardReaderTypesDeleteParams object
// with the ability to set a timeout on a request.
func NewCardReaderTypesDeleteParamsWithTimeout(timeout time.Duration) *CardReaderTypesDeleteParams {
	return &CardReaderTypesDeleteParams{
		timeout: timeout,
	}
}

// NewCardReaderTypesDeleteParamsWithContext creates a new CardReaderTypesDeleteParams object
// with the ability to set a context for a request.
func NewCardReaderTypesDeleteParamsWithContext(ctx context.Context) *CardReaderTypesDeleteParams {
	return &CardReaderTypesDeleteParams{
		Context: ctx,
	}
}

// NewCardReaderTypesDeleteParamsWithHTTPClient creates a new CardReaderTypesDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewCardReaderTypesDeleteParamsWithHTTPClient(client *http.Client) *CardReaderTypesDeleteParams {
	return &CardReaderTypesDeleteParams{
		HTTPClient: client,
	}
}

/*
CardReaderTypesDeleteParams contains all the parameters to send to the API endpoint

	for the card reader types delete operation.

	Typically these are written to a http.Request.
*/
type CardReaderTypesDeleteParams struct {

	/* ID.

	   The id of the resource to be deleted
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the card reader types delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CardReaderTypesDeleteParams) WithDefaults() *CardReaderTypesDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the card reader types delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CardReaderTypesDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the card reader types delete params
func (o *CardReaderTypesDeleteParams) WithTimeout(timeout time.Duration) *CardReaderTypesDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the card reader types delete params
func (o *CardReaderTypesDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the card reader types delete params
func (o *CardReaderTypesDeleteParams) WithContext(ctx context.Context) *CardReaderTypesDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the card reader types delete params
func (o *CardReaderTypesDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the card reader types delete params
func (o *CardReaderTypesDeleteParams) WithHTTPClient(client *http.Client) *CardReaderTypesDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the card reader types delete params
func (o *CardReaderTypesDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the card reader types delete params
func (o *CardReaderTypesDeleteParams) WithID(id string) *CardReaderTypesDeleteParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the card reader types delete params
func (o *CardReaderTypesDeleteParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *CardReaderTypesDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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