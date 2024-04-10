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

// NewBusinessUnitsCreateParams creates a new BusinessUnitsCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBusinessUnitsCreateParams() *BusinessUnitsCreateParams {
	return &BusinessUnitsCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBusinessUnitsCreateParamsWithTimeout creates a new BusinessUnitsCreateParams object
// with the ability to set a timeout on a request.
func NewBusinessUnitsCreateParamsWithTimeout(timeout time.Duration) *BusinessUnitsCreateParams {
	return &BusinessUnitsCreateParams{
		timeout: timeout,
	}
}

// NewBusinessUnitsCreateParamsWithContext creates a new BusinessUnitsCreateParams object
// with the ability to set a context for a request.
func NewBusinessUnitsCreateParamsWithContext(ctx context.Context) *BusinessUnitsCreateParams {
	return &BusinessUnitsCreateParams{
		Context: ctx,
	}
}

// NewBusinessUnitsCreateParamsWithHTTPClient creates a new BusinessUnitsCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewBusinessUnitsCreateParamsWithHTTPClient(client *http.Client) *BusinessUnitsCreateParams {
	return &BusinessUnitsCreateParams{
		HTTPClient: client,
	}
}

/*
BusinessUnitsCreateParams contains all the parameters to send to the API endpoint

	for the business units create operation.

	Typically these are written to a http.Request.
*/
type BusinessUnitsCreateParams struct {

	// Data.
	Data *models.BusinessUnit

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the business units create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BusinessUnitsCreateParams) WithDefaults() *BusinessUnitsCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the business units create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BusinessUnitsCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the business units create params
func (o *BusinessUnitsCreateParams) WithTimeout(timeout time.Duration) *BusinessUnitsCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the business units create params
func (o *BusinessUnitsCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the business units create params
func (o *BusinessUnitsCreateParams) WithContext(ctx context.Context) *BusinessUnitsCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the business units create params
func (o *BusinessUnitsCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the business units create params
func (o *BusinessUnitsCreateParams) WithHTTPClient(client *http.Client) *BusinessUnitsCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the business units create params
func (o *BusinessUnitsCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the business units create params
func (o *BusinessUnitsCreateParams) WithData(data *models.BusinessUnit) *BusinessUnitsCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the business units create params
func (o *BusinessUnitsCreateParams) SetData(data *models.BusinessUnit) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *BusinessUnitsCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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