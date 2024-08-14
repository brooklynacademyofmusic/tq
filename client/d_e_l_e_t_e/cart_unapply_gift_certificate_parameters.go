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

// NewCartUnapplyGiftCertificateParams creates a new CartUnapplyGiftCertificateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCartUnapplyGiftCertificateParams() *CartUnapplyGiftCertificateParams {
	return &CartUnapplyGiftCertificateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCartUnapplyGiftCertificateParamsWithTimeout creates a new CartUnapplyGiftCertificateParams object
// with the ability to set a timeout on a request.
func NewCartUnapplyGiftCertificateParamsWithTimeout(timeout time.Duration) *CartUnapplyGiftCertificateParams {
	return &CartUnapplyGiftCertificateParams{
		timeout: timeout,
	}
}

// NewCartUnapplyGiftCertificateParamsWithContext creates a new CartUnapplyGiftCertificateParams object
// with the ability to set a context for a request.
func NewCartUnapplyGiftCertificateParamsWithContext(ctx context.Context) *CartUnapplyGiftCertificateParams {
	return &CartUnapplyGiftCertificateParams{
		Context: ctx,
	}
}

// NewCartUnapplyGiftCertificateParamsWithHTTPClient creates a new CartUnapplyGiftCertificateParams object
// with the ability to set a custom HTTPClient for a request.
func NewCartUnapplyGiftCertificateParamsWithHTTPClient(client *http.Client) *CartUnapplyGiftCertificateParams {
	return &CartUnapplyGiftCertificateParams{
		HTTPClient: client,
	}
}

/*
CartUnapplyGiftCertificateParams contains all the parameters to send to the API endpoint

	for the cart unapply gift certificate operation.

	Typically these are written to a http.Request.
*/
type CartUnapplyGiftCertificateParams struct {

	/* GiftCertificateNumber.

	   Must be a valid gift certificate that has value applied to the cart as a payment.
	*/
	GiftCertificateNumber string

	// SessionKey.
	SessionKey string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the cart unapply gift certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CartUnapplyGiftCertificateParams) WithDefaults() *CartUnapplyGiftCertificateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the cart unapply gift certificate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CartUnapplyGiftCertificateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) WithTimeout(timeout time.Duration) *CartUnapplyGiftCertificateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) WithContext(ctx context.Context) *CartUnapplyGiftCertificateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) WithHTTPClient(client *http.Client) *CartUnapplyGiftCertificateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGiftCertificateNumber adds the giftCertificateNumber to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) WithGiftCertificateNumber(giftCertificateNumber string) *CartUnapplyGiftCertificateParams {
	o.SetGiftCertificateNumber(giftCertificateNumber)
	return o
}

// SetGiftCertificateNumber adds the giftCertificateNumber to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) SetGiftCertificateNumber(giftCertificateNumber string) {
	o.GiftCertificateNumber = giftCertificateNumber
}

// WithSessionKey adds the sessionKey to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) WithSessionKey(sessionKey string) *CartUnapplyGiftCertificateParams {
	o.SetSessionKey(sessionKey)
	return o
}

// SetSessionKey adds the sessionKey to the cart unapply gift certificate params
func (o *CartUnapplyGiftCertificateParams) SetSessionKey(sessionKey string) {
	o.SessionKey = sessionKey
}

// WriteToRequest writes these params to a swagger request
func (o *CartUnapplyGiftCertificateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param giftCertificateNumber
	if err := r.SetPathParam("giftCertificateNumber", o.GiftCertificateNumber); err != nil {
		return err
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