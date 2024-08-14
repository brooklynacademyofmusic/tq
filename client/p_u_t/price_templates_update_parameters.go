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

// NewPriceTemplatesUpdateParams creates a new PriceTemplatesUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPriceTemplatesUpdateParams() *PriceTemplatesUpdateParams {
	return &PriceTemplatesUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPriceTemplatesUpdateParamsWithTimeout creates a new PriceTemplatesUpdateParams object
// with the ability to set a timeout on a request.
func NewPriceTemplatesUpdateParamsWithTimeout(timeout time.Duration) *PriceTemplatesUpdateParams {
	return &PriceTemplatesUpdateParams{
		timeout: timeout,
	}
}

// NewPriceTemplatesUpdateParamsWithContext creates a new PriceTemplatesUpdateParams object
// with the ability to set a context for a request.
func NewPriceTemplatesUpdateParamsWithContext(ctx context.Context) *PriceTemplatesUpdateParams {
	return &PriceTemplatesUpdateParams{
		Context: ctx,
	}
}

// NewPriceTemplatesUpdateParamsWithHTTPClient creates a new PriceTemplatesUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewPriceTemplatesUpdateParamsWithHTTPClient(client *http.Client) *PriceTemplatesUpdateParams {
	return &PriceTemplatesUpdateParams{
		HTTPClient: client,
	}
}

/*
PriceTemplatesUpdateParams contains all the parameters to send to the API endpoint

	for the price templates update operation.

	Typically these are written to a http.Request.
*/
type PriceTemplatesUpdateParams struct {

	// PriceTemplate.
	PriceTemplate *models.PriceTemplate

	// PriceTemplateID.
	PriceTemplateID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the price templates update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceTemplatesUpdateParams) WithDefaults() *PriceTemplatesUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the price templates update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceTemplatesUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the price templates update params
func (o *PriceTemplatesUpdateParams) WithTimeout(timeout time.Duration) *PriceTemplatesUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the price templates update params
func (o *PriceTemplatesUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the price templates update params
func (o *PriceTemplatesUpdateParams) WithContext(ctx context.Context) *PriceTemplatesUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the price templates update params
func (o *PriceTemplatesUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the price templates update params
func (o *PriceTemplatesUpdateParams) WithHTTPClient(client *http.Client) *PriceTemplatesUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the price templates update params
func (o *PriceTemplatesUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPriceTemplate adds the priceTemplate to the price templates update params
func (o *PriceTemplatesUpdateParams) WithPriceTemplate(priceTemplate *models.PriceTemplate) *PriceTemplatesUpdateParams {
	o.SetPriceTemplate(priceTemplate)
	return o
}

// SetPriceTemplate adds the priceTemplate to the price templates update params
func (o *PriceTemplatesUpdateParams) SetPriceTemplate(priceTemplate *models.PriceTemplate) {
	o.PriceTemplate = priceTemplate
}

// WithPriceTemplateID adds the priceTemplateID to the price templates update params
func (o *PriceTemplatesUpdateParams) WithPriceTemplateID(priceTemplateID string) *PriceTemplatesUpdateParams {
	o.SetPriceTemplateID(priceTemplateID)
	return o
}

// SetPriceTemplateID adds the priceTemplateId to the price templates update params
func (o *PriceTemplatesUpdateParams) SetPriceTemplateID(priceTemplateID string) {
	o.PriceTemplateID = priceTemplateID
}

// WriteToRequest writes these params to a swagger request
func (o *PriceTemplatesUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.PriceTemplate != nil {
		if err := r.SetBodyParam(o.PriceTemplate); err != nil {
			return err
		}
	}

	// path param priceTemplateId
	if err := r.SetPathParam("priceTemplateId", o.PriceTemplateID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}