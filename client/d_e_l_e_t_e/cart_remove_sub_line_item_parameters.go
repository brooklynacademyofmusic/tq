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

// NewCartRemoveSubLineItemParams creates a new CartRemoveSubLineItemParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCartRemoveSubLineItemParams() *CartRemoveSubLineItemParams {
	return &CartRemoveSubLineItemParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCartRemoveSubLineItemParamsWithTimeout creates a new CartRemoveSubLineItemParams object
// with the ability to set a timeout on a request.
func NewCartRemoveSubLineItemParamsWithTimeout(timeout time.Duration) *CartRemoveSubLineItemParams {
	return &CartRemoveSubLineItemParams{
		timeout: timeout,
	}
}

// NewCartRemoveSubLineItemParamsWithContext creates a new CartRemoveSubLineItemParams object
// with the ability to set a context for a request.
func NewCartRemoveSubLineItemParamsWithContext(ctx context.Context) *CartRemoveSubLineItemParams {
	return &CartRemoveSubLineItemParams{
		Context: ctx,
	}
}

// NewCartRemoveSubLineItemParamsWithHTTPClient creates a new CartRemoveSubLineItemParams object
// with the ability to set a custom HTTPClient for a request.
func NewCartRemoveSubLineItemParamsWithHTTPClient(client *http.Client) *CartRemoveSubLineItemParams {
	return &CartRemoveSubLineItemParams{
		HTTPClient: client,
	}
}

/*
CartRemoveSubLineItemParams contains all the parameters to send to the API endpoint

	for the cart remove sub line item operation.

	Typically these are written to a http.Request.
*/
type CartRemoveSubLineItemParams struct {

	/* LineItemID.

	   The Id of the line item parent of the sub line item.
	*/
	LineItemID string

	// SessionKey.
	SessionKey string

	/* SubLineItemID.

	   The Id of the sub line item to delete.
	*/
	SubLineItemID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the cart remove sub line item params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CartRemoveSubLineItemParams) WithDefaults() *CartRemoveSubLineItemParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the cart remove sub line item params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CartRemoveSubLineItemParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) WithTimeout(timeout time.Duration) *CartRemoveSubLineItemParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) WithContext(ctx context.Context) *CartRemoveSubLineItemParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) WithHTTPClient(client *http.Client) *CartRemoveSubLineItemParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithLineItemID adds the lineItemID to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) WithLineItemID(lineItemID string) *CartRemoveSubLineItemParams {
	o.SetLineItemID(lineItemID)
	return o
}

// SetLineItemID adds the lineItemId to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) SetLineItemID(lineItemID string) {
	o.LineItemID = lineItemID
}

// WithSessionKey adds the sessionKey to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) WithSessionKey(sessionKey string) *CartRemoveSubLineItemParams {
	o.SetSessionKey(sessionKey)
	return o
}

// SetSessionKey adds the sessionKey to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) SetSessionKey(sessionKey string) {
	o.SessionKey = sessionKey
}

// WithSubLineItemID adds the subLineItemID to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) WithSubLineItemID(subLineItemID string) *CartRemoveSubLineItemParams {
	o.SetSubLineItemID(subLineItemID)
	return o
}

// SetSubLineItemID adds the subLineItemId to the cart remove sub line item params
func (o *CartRemoveSubLineItemParams) SetSubLineItemID(subLineItemID string) {
	o.SubLineItemID = subLineItemID
}

// WriteToRequest writes these params to a swagger request
func (o *CartRemoveSubLineItemParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param lineItemId
	if err := r.SetPathParam("lineItemId", o.LineItemID); err != nil {
		return err
	}

	// path param sessionKey
	if err := r.SetPathParam("sessionKey", o.SessionKey); err != nil {
		return err
	}

	// path param subLineItemId
	if err := r.SetPathParam("subLineItemId", o.SubLineItemID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}