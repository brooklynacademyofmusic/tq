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

// NewHoldCodeCategoriesCreateParams creates a new HoldCodeCategoriesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewHoldCodeCategoriesCreateParams() *HoldCodeCategoriesCreateParams {
	return &HoldCodeCategoriesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewHoldCodeCategoriesCreateParamsWithTimeout creates a new HoldCodeCategoriesCreateParams object
// with the ability to set a timeout on a request.
func NewHoldCodeCategoriesCreateParamsWithTimeout(timeout time.Duration) *HoldCodeCategoriesCreateParams {
	return &HoldCodeCategoriesCreateParams{
		timeout: timeout,
	}
}

// NewHoldCodeCategoriesCreateParamsWithContext creates a new HoldCodeCategoriesCreateParams object
// with the ability to set a context for a request.
func NewHoldCodeCategoriesCreateParamsWithContext(ctx context.Context) *HoldCodeCategoriesCreateParams {
	return &HoldCodeCategoriesCreateParams{
		Context: ctx,
	}
}

// NewHoldCodeCategoriesCreateParamsWithHTTPClient creates a new HoldCodeCategoriesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewHoldCodeCategoriesCreateParamsWithHTTPClient(client *http.Client) *HoldCodeCategoriesCreateParams {
	return &HoldCodeCategoriesCreateParams{
		HTTPClient: client,
	}
}

/*
HoldCodeCategoriesCreateParams contains all the parameters to send to the API endpoint

	for the hold code categories create operation.

	Typically these are written to a http.Request.
*/
type HoldCodeCategoriesCreateParams struct {

	/* Data.

	   The resource to be created
	*/
	Data *models.HoldCodeCategory

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the hold code categories create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *HoldCodeCategoriesCreateParams) WithDefaults() *HoldCodeCategoriesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the hold code categories create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *HoldCodeCategoriesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) WithTimeout(timeout time.Duration) *HoldCodeCategoriesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) WithContext(ctx context.Context) *HoldCodeCategoriesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) WithHTTPClient(client *http.Client) *HoldCodeCategoriesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithData adds the data to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) WithData(data *models.HoldCodeCategory) *HoldCodeCategoriesCreateParams {
	o.SetData(data)
	return o
}

// SetData adds the data to the hold code categories create params
func (o *HoldCodeCategoriesCreateParams) SetData(data *models.HoldCodeCategory) {
	o.Data = data
}

// WriteToRequest writes these params to a swagger request
func (o *HoldCodeCategoriesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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