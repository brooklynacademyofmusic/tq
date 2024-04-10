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

// NewPaymentMethodGroupsDeleteParams creates a new PaymentMethodGroupsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentMethodGroupsDeleteParams() *PaymentMethodGroupsDeleteParams {
	return &PaymentMethodGroupsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentMethodGroupsDeleteParamsWithTimeout creates a new PaymentMethodGroupsDeleteParams object
// with the ability to set a timeout on a request.
func NewPaymentMethodGroupsDeleteParamsWithTimeout(timeout time.Duration) *PaymentMethodGroupsDeleteParams {
	return &PaymentMethodGroupsDeleteParams{
		timeout: timeout,
	}
}

// NewPaymentMethodGroupsDeleteParamsWithContext creates a new PaymentMethodGroupsDeleteParams object
// with the ability to set a context for a request.
func NewPaymentMethodGroupsDeleteParamsWithContext(ctx context.Context) *PaymentMethodGroupsDeleteParams {
	return &PaymentMethodGroupsDeleteParams{
		Context: ctx,
	}
}

// NewPaymentMethodGroupsDeleteParamsWithHTTPClient creates a new PaymentMethodGroupsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentMethodGroupsDeleteParamsWithHTTPClient(client *http.Client) *PaymentMethodGroupsDeleteParams {
	return &PaymentMethodGroupsDeleteParams{
		HTTPClient: client,
	}
}

/*
PaymentMethodGroupsDeleteParams contains all the parameters to send to the API endpoint

	for the payment method groups delete operation.

	Typically these are written to a http.Request.
*/
type PaymentMethodGroupsDeleteParams struct {

	// ID.
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the payment method groups delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodGroupsDeleteParams) WithDefaults() *PaymentMethodGroupsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payment method groups delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodGroupsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) WithTimeout(timeout time.Duration) *PaymentMethodGroupsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) WithContext(ctx context.Context) *PaymentMethodGroupsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) WithHTTPClient(client *http.Client) *PaymentMethodGroupsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) WithID(id string) *PaymentMethodGroupsDeleteParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the payment method groups delete params
func (o *PaymentMethodGroupsDeleteParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentMethodGroupsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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