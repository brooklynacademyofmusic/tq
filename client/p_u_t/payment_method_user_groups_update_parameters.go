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

// NewPaymentMethodUserGroupsUpdateParams creates a new PaymentMethodUserGroupsUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentMethodUserGroupsUpdateParams() *PaymentMethodUserGroupsUpdateParams {
	return &PaymentMethodUserGroupsUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentMethodUserGroupsUpdateParamsWithTimeout creates a new PaymentMethodUserGroupsUpdateParams object
// with the ability to set a timeout on a request.
func NewPaymentMethodUserGroupsUpdateParamsWithTimeout(timeout time.Duration) *PaymentMethodUserGroupsUpdateParams {
	return &PaymentMethodUserGroupsUpdateParams{
		timeout: timeout,
	}
}

// NewPaymentMethodUserGroupsUpdateParamsWithContext creates a new PaymentMethodUserGroupsUpdateParams object
// with the ability to set a context for a request.
func NewPaymentMethodUserGroupsUpdateParamsWithContext(ctx context.Context) *PaymentMethodUserGroupsUpdateParams {
	return &PaymentMethodUserGroupsUpdateParams{
		Context: ctx,
	}
}

// NewPaymentMethodUserGroupsUpdateParamsWithHTTPClient creates a new PaymentMethodUserGroupsUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentMethodUserGroupsUpdateParamsWithHTTPClient(client *http.Client) *PaymentMethodUserGroupsUpdateParams {
	return &PaymentMethodUserGroupsUpdateParams{
		HTTPClient: client,
	}
}

/*
PaymentMethodUserGroupsUpdateParams contains all the parameters to send to the API endpoint

	for the payment method user groups update operation.

	Typically these are written to a http.Request.
*/
type PaymentMethodUserGroupsUpdateParams struct {

	// PaymentMethodUserGroup.
	PaymentMethodUserGroup *models.PaymentMethodUserGroup

	// PaymentMethodUserGroupID.
	PaymentMethodUserGroupID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the payment method user groups update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodUserGroupsUpdateParams) WithDefaults() *PaymentMethodUserGroupsUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payment method user groups update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodUserGroupsUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) WithTimeout(timeout time.Duration) *PaymentMethodUserGroupsUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) WithContext(ctx context.Context) *PaymentMethodUserGroupsUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) WithHTTPClient(client *http.Client) *PaymentMethodUserGroupsUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithPaymentMethodUserGroup adds the paymentMethodUserGroup to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) WithPaymentMethodUserGroup(paymentMethodUserGroup *models.PaymentMethodUserGroup) *PaymentMethodUserGroupsUpdateParams {
	o.SetPaymentMethodUserGroup(paymentMethodUserGroup)
	return o
}

// SetPaymentMethodUserGroup adds the paymentMethodUserGroup to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) SetPaymentMethodUserGroup(paymentMethodUserGroup *models.PaymentMethodUserGroup) {
	o.PaymentMethodUserGroup = paymentMethodUserGroup
}

// WithPaymentMethodUserGroupID adds the paymentMethodUserGroupID to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) WithPaymentMethodUserGroupID(paymentMethodUserGroupID string) *PaymentMethodUserGroupsUpdateParams {
	o.SetPaymentMethodUserGroupID(paymentMethodUserGroupID)
	return o
}

// SetPaymentMethodUserGroupID adds the paymentMethodUserGroupId to the payment method user groups update params
func (o *PaymentMethodUserGroupsUpdateParams) SetPaymentMethodUserGroupID(paymentMethodUserGroupID string) {
	o.PaymentMethodUserGroupID = paymentMethodUserGroupID
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentMethodUserGroupsUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.PaymentMethodUserGroup != nil {
		if err := r.SetBodyParam(o.PaymentMethodUserGroup); err != nil {
			return err
		}
	}

	// path param paymentMethodUserGroupId
	if err := r.SetPathParam("paymentMethodUserGroupId", o.PaymentMethodUserGroupID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}