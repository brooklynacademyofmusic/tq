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

// NewPaymentMethodUserGroupsDeleteParams creates a new PaymentMethodUserGroupsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentMethodUserGroupsDeleteParams() *PaymentMethodUserGroupsDeleteParams {
	return &PaymentMethodUserGroupsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentMethodUserGroupsDeleteParamsWithTimeout creates a new PaymentMethodUserGroupsDeleteParams object
// with the ability to set a timeout on a request.
func NewPaymentMethodUserGroupsDeleteParamsWithTimeout(timeout time.Duration) *PaymentMethodUserGroupsDeleteParams {
	return &PaymentMethodUserGroupsDeleteParams{
		timeout: timeout,
	}
}

// NewPaymentMethodUserGroupsDeleteParamsWithContext creates a new PaymentMethodUserGroupsDeleteParams object
// with the ability to set a context for a request.
func NewPaymentMethodUserGroupsDeleteParamsWithContext(ctx context.Context) *PaymentMethodUserGroupsDeleteParams {
	return &PaymentMethodUserGroupsDeleteParams{
		Context: ctx,
	}
}

// NewPaymentMethodUserGroupsDeleteParamsWithHTTPClient creates a new PaymentMethodUserGroupsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentMethodUserGroupsDeleteParamsWithHTTPClient(client *http.Client) *PaymentMethodUserGroupsDeleteParams {
	return &PaymentMethodUserGroupsDeleteParams{
		HTTPClient: client,
	}
}

/*
PaymentMethodUserGroupsDeleteParams contains all the parameters to send to the API endpoint

	for the payment method user groups delete operation.

	Typically these are written to a http.Request.
*/
type PaymentMethodUserGroupsDeleteParams struct {

	// PaymentMethodUserGroupID.
	PaymentMethodUserGroupID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the payment method user groups delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodUserGroupsDeleteParams) WithDefaults() *PaymentMethodUserGroupsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payment method user groups delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodUserGroupsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) WithTimeout(timeout time.Duration) *PaymentMethodUserGroupsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) WithContext(ctx context.Context) *PaymentMethodUserGroupsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) WithHTTPClient(client *http.Client) *PaymentMethodUserGroupsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPaymentMethodUserGroupID adds the paymentMethodUserGroupID to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) WithPaymentMethodUserGroupID(paymentMethodUserGroupID string) *PaymentMethodUserGroupsDeleteParams {
	o.SetPaymentMethodUserGroupID(paymentMethodUserGroupID)
	return o
}

// SetPaymentMethodUserGroupID adds the paymentMethodUserGroupId to the payment method user groups delete params
func (o *PaymentMethodUserGroupsDeleteParams) SetPaymentMethodUserGroupID(paymentMethodUserGroupID string) {
	o.PaymentMethodUserGroupID = paymentMethodUserGroupID
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentMethodUserGroupsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param paymentMethodUserGroupId
	if err := r.SetPathParam("paymentMethodUserGroupId", o.PaymentMethodUserGroupID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}