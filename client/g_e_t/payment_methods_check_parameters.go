// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

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

// NewPaymentMethodsCheckParams creates a new PaymentMethodsCheckParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentMethodsCheckParams() *PaymentMethodsCheckParams {
	return &PaymentMethodsCheckParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentMethodsCheckParamsWithTimeout creates a new PaymentMethodsCheckParams object
// with the ability to set a timeout on a request.
func NewPaymentMethodsCheckParamsWithTimeout(timeout time.Duration) *PaymentMethodsCheckParams {
	return &PaymentMethodsCheckParams{
		timeout: timeout,
	}
}

// NewPaymentMethodsCheckParamsWithContext creates a new PaymentMethodsCheckParams object
// with the ability to set a context for a request.
func NewPaymentMethodsCheckParamsWithContext(ctx context.Context) *PaymentMethodsCheckParams {
	return &PaymentMethodsCheckParams{
		Context: ctx,
	}
}

// NewPaymentMethodsCheckParamsWithHTTPClient creates a new PaymentMethodsCheckParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentMethodsCheckParamsWithHTTPClient(client *http.Client) *PaymentMethodsCheckParams {
	return &PaymentMethodsCheckParams{
		HTTPClient: client,
	}
}

/*
PaymentMethodsCheckParams contains all the parameters to send to the API endpoint

	for the payment methods check operation.

	Typically these are written to a http.Request.
*/
type PaymentMethodsCheckParams struct {

	// CardReaderTypeID.
	CardReaderTypeID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the payment methods check params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodsCheckParams) WithDefaults() *PaymentMethodsCheckParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payment methods check params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentMethodsCheckParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payment methods check params
func (o *PaymentMethodsCheckParams) WithTimeout(timeout time.Duration) *PaymentMethodsCheckParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payment methods check params
func (o *PaymentMethodsCheckParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payment methods check params
func (o *PaymentMethodsCheckParams) WithContext(ctx context.Context) *PaymentMethodsCheckParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payment methods check params
func (o *PaymentMethodsCheckParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payment methods check params
func (o *PaymentMethodsCheckParams) WithHTTPClient(client *http.Client) *PaymentMethodsCheckParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payment methods check params
func (o *PaymentMethodsCheckParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCardReaderTypeID adds the cardReaderTypeID to the payment methods check params
func (o *PaymentMethodsCheckParams) WithCardReaderTypeID(cardReaderTypeID string) *PaymentMethodsCheckParams {
	o.SetCardReaderTypeID(cardReaderTypeID)
	return o
}

// SetCardReaderTypeID adds the cardReaderTypeId to the payment methods check params
func (o *PaymentMethodsCheckParams) SetCardReaderTypeID(cardReaderTypeID string) {
	o.CardReaderTypeID = cardReaderTypeID
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentMethodsCheckParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param cardReaderTypeId
	qrCardReaderTypeID := o.CardReaderTypeID
	qCardReaderTypeID := qrCardReaderTypeID
	if qCardReaderTypeID != "" {

		if err := r.SetQueryParam("cardReaderTypeId", qCardReaderTypeID); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}