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

// NewPaymentSignaturesPostForOrderParams creates a new PaymentSignaturesPostForOrderParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentSignaturesPostForOrderParams() *PaymentSignaturesPostForOrderParams {
	return &PaymentSignaturesPostForOrderParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentSignaturesPostForOrderParamsWithTimeout creates a new PaymentSignaturesPostForOrderParams object
// with the ability to set a timeout on a request.
func NewPaymentSignaturesPostForOrderParamsWithTimeout(timeout time.Duration) *PaymentSignaturesPostForOrderParams {
	return &PaymentSignaturesPostForOrderParams{
		timeout: timeout,
	}
}

// NewPaymentSignaturesPostForOrderParamsWithContext creates a new PaymentSignaturesPostForOrderParams object
// with the ability to set a context for a request.
func NewPaymentSignaturesPostForOrderParamsWithContext(ctx context.Context) *PaymentSignaturesPostForOrderParams {
	return &PaymentSignaturesPostForOrderParams{
		Context: ctx,
	}
}

// NewPaymentSignaturesPostForOrderParamsWithHTTPClient creates a new PaymentSignaturesPostForOrderParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentSignaturesPostForOrderParamsWithHTTPClient(client *http.Client) *PaymentSignaturesPostForOrderParams {
	return &PaymentSignaturesPostForOrderParams{
		HTTPClient: client,
	}
}

/*
PaymentSignaturesPostForOrderParams contains all the parameters to send to the API endpoint

	for the payment signatures post for order operation.

	Typically these are written to a http.Request.
*/
type PaymentSignaturesPostForOrderParams struct {

	// OrderID.
	OrderID string

	// PaymentSignature.
	PaymentSignature *models.PaymentSignature

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the payment signatures post for order params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentSignaturesPostForOrderParams) WithDefaults() *PaymentSignaturesPostForOrderParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payment signatures post for order params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentSignaturesPostForOrderParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) WithTimeout(timeout time.Duration) *PaymentSignaturesPostForOrderParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) WithContext(ctx context.Context) *PaymentSignaturesPostForOrderParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) WithHTTPClient(client *http.Client) *PaymentSignaturesPostForOrderParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOrderID adds the orderID to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) WithOrderID(orderID string) *PaymentSignaturesPostForOrderParams {
	o.SetOrderID(orderID)
	return o
}

// SetOrderID adds the orderId to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) SetOrderID(orderID string) {
	o.OrderID = orderID
}

// WithPaymentSignature adds the paymentSignature to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) WithPaymentSignature(paymentSignature *models.PaymentSignature) *PaymentSignaturesPostForOrderParams {
	o.SetPaymentSignature(paymentSignature)
	return o
}

// SetPaymentSignature adds the paymentSignature to the payment signatures post for order params
func (o *PaymentSignaturesPostForOrderParams) SetPaymentSignature(paymentSignature *models.PaymentSignature) {
	o.PaymentSignature = paymentSignature
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentSignaturesPostForOrderParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param orderId
	if err := r.SetPathParam("orderId", o.OrderID); err != nil {
		return err
	}
	if o.PaymentSignature != nil {
		if err := r.SetBodyParam(o.PaymentSignature); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}