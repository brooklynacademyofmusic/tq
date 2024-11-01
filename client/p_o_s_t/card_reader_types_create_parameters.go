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

// NewCardReaderTypesCreateParams creates a new CardReaderTypesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCardReaderTypesCreateParams() *CardReaderTypesCreateParams {
	return &CardReaderTypesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCardReaderTypesCreateParamsWithTimeout creates a new CardReaderTypesCreateParams object
// with the ability to set a timeout on a request.
func NewCardReaderTypesCreateParamsWithTimeout(timeout time.Duration) *CardReaderTypesCreateParams {
	return &CardReaderTypesCreateParams{
		timeout: timeout,
	}
}

// NewCardReaderTypesCreateParamsWithContext creates a new CardReaderTypesCreateParams object
// with the ability to set a context for a request.
func NewCardReaderTypesCreateParamsWithContext(ctx context.Context) *CardReaderTypesCreateParams {
	return &CardReaderTypesCreateParams{
		Context: ctx,
	}
}

// NewCardReaderTypesCreateParamsWithHTTPClient creates a new CardReaderTypesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewCardReaderTypesCreateParamsWithHTTPClient(client *http.Client) *CardReaderTypesCreateParams {
	return &CardReaderTypesCreateParams{
		HTTPClient: client,
	}
}

/*
CardReaderTypesCreateParams contains all the parameters to send to the API endpoint

	for the card reader types create operation.

	Typically these are written to a http.Request.
*/
type CardReaderTypesCreateParams struct {

	/* Data.

	   The resource to be created
	*/
	Data *models.CardReaderType

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the card reader types create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CardReaderTypesCreateParams) WithDefaults() *CardReaderTypesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the card reader types create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CardReaderTypesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the card reader types create params
func (o *CardReaderTypesCreateParams) WithTimeout(timeout time.Duration) *CardReaderTypesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the card reader types create params
func (o *CardReaderTypesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the card reader types create params
func (o *CardReaderTypesCreateParams) WithContext(ctx context.Context) *CardReaderTypesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the card reader types create params
func (o *CardReaderTypesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the card reader types create params
func (o *CardReaderTypesCreateParams) WithHTTPClient(client *http.Client) *CardReaderTypesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the card reader types create params
func (o *CardReaderTypesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the card reader types create params
func (o *CardReaderTypesCreateParams) WithData(data *models.CardReaderType) *CardReaderTypesCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the card reader types create params
func (o *CardReaderTypesCreateParams) SetData(data *models.CardReaderType) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *CardReaderTypesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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