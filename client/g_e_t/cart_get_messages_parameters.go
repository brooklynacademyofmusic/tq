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

// NewCartGetMessagesParams creates a new CartGetMessagesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCartGetMessagesParams() *CartGetMessagesParams {
	return &CartGetMessagesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCartGetMessagesParamsWithTimeout creates a new CartGetMessagesParams object
// with the ability to set a timeout on a request.
func NewCartGetMessagesParamsWithTimeout(timeout time.Duration) *CartGetMessagesParams {
	return &CartGetMessagesParams{
		timeout: timeout,
	}
}

// NewCartGetMessagesParamsWithContext creates a new CartGetMessagesParams object
// with the ability to set a context for a request.
func NewCartGetMessagesParamsWithContext(ctx context.Context) *CartGetMessagesParams {
	return &CartGetMessagesParams{
		Context: ctx,
	}
}

// NewCartGetMessagesParamsWithHTTPClient creates a new CartGetMessagesParams object
// with the ability to set a custom HTTPClient for a request.
func NewCartGetMessagesParamsWithHTTPClient(client *http.Client) *CartGetMessagesParams {
	return &CartGetMessagesParams{
		HTTPClient: client,
	}
}

/*
CartGetMessagesParams contains all the parameters to send to the API endpoint

	for the cart get messages operation.

	Typically these are written to a http.Request.
*/
type CartGetMessagesParams struct {

	/* MessageTypes.

	   A comma delimited list of valid message type ids (/ReferenceData/PricingRuleMessageTypes)
	*/
	MessageTypes *string

	/* SavedCart.

	   Pass True if Checkout has already been called for the cart.
	*/
	SavedCart *string

	// SessionKey.
	SessionKey string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the cart get messages params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CartGetMessagesParams) WithDefaults() *CartGetMessagesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the cart get messages params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CartGetMessagesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the cart get messages params
func (o *CartGetMessagesParams) WithTimeout(timeout time.Duration) *CartGetMessagesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the cart get messages params
func (o *CartGetMessagesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the cart get messages params
func (o *CartGetMessagesParams) WithContext(ctx context.Context) *CartGetMessagesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the cart get messages params
func (o *CartGetMessagesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the cart get messages params
func (o *CartGetMessagesParams) WithHTTPClient(client *http.Client) *CartGetMessagesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the cart get messages params
func (o *CartGetMessagesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMessageTypes adds the messageTypes to the cart get messages params
func (o *CartGetMessagesParams) WithMessageTypes(messageTypes *string) *CartGetMessagesParams {
	o.SetMessageTypes(messageTypes)
	return o
}

// SetMessageTypes adds the messageTypes to the cart get messages params
func (o *CartGetMessagesParams) SetMessageTypes(messageTypes *string) {
	o.MessageTypes = messageTypes
}

// WithSavedCart adds the savedCart to the cart get messages params
func (o *CartGetMessagesParams) WithSavedCart(savedCart *string) *CartGetMessagesParams {
	o.SetSavedCart(savedCart)
	return o
}

// SetSavedCart adds the savedCart to the cart get messages params
func (o *CartGetMessagesParams) SetSavedCart(savedCart *string) {
	o.SavedCart = savedCart
}

// WithSessionKey adds the sessionKey to the cart get messages params
func (o *CartGetMessagesParams) WithSessionKey(sessionKey string) *CartGetMessagesParams {
	o.SetSessionKey(sessionKey)
	return o
}

// SetSessionKey adds the sessionKey to the cart get messages params
func (o *CartGetMessagesParams) SetSessionKey(sessionKey string) {
	o.SessionKey = sessionKey
}

// WriteToRequest writes these params to a swagger request
func (o *CartGetMessagesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.MessageTypes != nil {

		// query param messageTypes
		var qrMessageTypes string

		if o.MessageTypes != nil {
			qrMessageTypes = *o.MessageTypes
		}
		qMessageTypes := qrMessageTypes
		if qMessageTypes != "" {

			if err := r.SetQueryParam("messageTypes", qMessageTypes); err != nil {
				return err
			}
		}
	}

	if o.SavedCart != nil {

		// query param savedCart
		var qrSavedCart string

		if o.SavedCart != nil {
			qrSavedCart = *o.SavedCart
		}
		qSavedCart := qrSavedCart
		if qSavedCart != "" {

			if err := r.SetQueryParam("savedCart", qSavedCart); err != nil {
				return err
			}
		}
	}

	// path param sessionKey
	if err := r.SetPathParam("sessionKey", o.SessionKey); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}