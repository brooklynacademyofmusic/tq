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

// NewOrderBillingReprintParams creates a new OrderBillingReprintParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOrderBillingReprintParams() *OrderBillingReprintParams {
	return &OrderBillingReprintParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOrderBillingReprintParamsWithTimeout creates a new OrderBillingReprintParams object
// with the ability to set a timeout on a request.
func NewOrderBillingReprintParamsWithTimeout(timeout time.Duration) *OrderBillingReprintParams {
	return &OrderBillingReprintParams{
		timeout: timeout,
	}
}

// NewOrderBillingReprintParamsWithContext creates a new OrderBillingReprintParams object
// with the ability to set a context for a request.
func NewOrderBillingReprintParamsWithContext(ctx context.Context) *OrderBillingReprintParams {
	return &OrderBillingReprintParams{
		Context: ctx,
	}
}

// NewOrderBillingReprintParamsWithHTTPClient creates a new OrderBillingReprintParams object
// with the ability to set a custom HTTPClient for a request.
func NewOrderBillingReprintParamsWithHTTPClient(client *http.Client) *OrderBillingReprintParams {
	return &OrderBillingReprintParams{
		HTTPClient: client,
	}
}

/*
OrderBillingReprintParams contains all the parameters to send to the API endpoint

	for the order billing reprint operation.

	Typically these are written to a http.Request.
*/
type OrderBillingReprintParams struct {

	// OrderBillingID.
	OrderBillingID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the order billing reprint params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OrderBillingReprintParams) WithDefaults() *OrderBillingReprintParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the order billing reprint params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OrderBillingReprintParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the order billing reprint params
func (o *OrderBillingReprintParams) WithTimeout(timeout time.Duration) *OrderBillingReprintParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the order billing reprint params
func (o *OrderBillingReprintParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the order billing reprint params
func (o *OrderBillingReprintParams) WithContext(ctx context.Context) *OrderBillingReprintParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the order billing reprint params
func (o *OrderBillingReprintParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the order billing reprint params
func (o *OrderBillingReprintParams) WithHTTPClient(client *http.Client) *OrderBillingReprintParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the order billing reprint params
func (o *OrderBillingReprintParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithOrderBillingID adds the orderBillingID to the order billing reprint params
func (o *OrderBillingReprintParams) WithOrderBillingID(orderBillingID string) *OrderBillingReprintParams {
	o.SetOrderBillingID(orderBillingID)
	return o
}

// SetOrderBillingID adds the orderBillingId to the order billing reprint params
func (o *OrderBillingReprintParams) SetOrderBillingID(orderBillingID string) {
	o.OrderBillingID = orderBillingID
}

// WriteToRequest writes these params to a swagger request
func (o *OrderBillingReprintParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param orderBillingId
	if err := r.SetPathParam("orderBillingId", o.OrderBillingID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}