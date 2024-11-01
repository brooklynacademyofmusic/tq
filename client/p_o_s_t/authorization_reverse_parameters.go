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

// NewAuthorizationReverseParams creates a new AuthorizationReverseParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAuthorizationReverseParams() *AuthorizationReverseParams {
	return &AuthorizationReverseParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAuthorizationReverseParamsWithTimeout creates a new AuthorizationReverseParams object
// with the ability to set a timeout on a request.
func NewAuthorizationReverseParamsWithTimeout(timeout time.Duration) *AuthorizationReverseParams {
	return &AuthorizationReverseParams{
		timeout: timeout,
	}
}

// NewAuthorizationReverseParamsWithContext creates a new AuthorizationReverseParams object
// with the ability to set a context for a request.
func NewAuthorizationReverseParamsWithContext(ctx context.Context) *AuthorizationReverseParams {
	return &AuthorizationReverseParams{
		Context: ctx,
	}
}

// NewAuthorizationReverseParamsWithHTTPClient creates a new AuthorizationReverseParams object
// with the ability to set a custom HTTPClient for a request.
func NewAuthorizationReverseParamsWithHTTPClient(client *http.Client) *AuthorizationReverseParams {
	return &AuthorizationReverseParams{
		HTTPClient: client,
	}
}

/*
AuthorizationReverseParams contains all the parameters to send to the API endpoint

	for the authorization reverse operation.

	Typically these are written to a http.Request.
*/
type AuthorizationReverseParams struct {

	/* ReferenceNumber.

	   Obtained from ReferenceNumber in the Authorization endpoint
	*/
	ReferenceNumber string

	// ReversalRequest.
	ReversalRequest *models.ReversalRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the authorization reverse params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AuthorizationReverseParams) WithDefaults() *AuthorizationReverseParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the authorization reverse params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AuthorizationReverseParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the authorization reverse params
func (o *AuthorizationReverseParams) WithTimeout(timeout time.Duration) *AuthorizationReverseParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the authorization reverse params
func (o *AuthorizationReverseParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the authorization reverse params
func (o *AuthorizationReverseParams) WithContext(ctx context.Context) *AuthorizationReverseParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the authorization reverse params
func (o *AuthorizationReverseParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the authorization reverse params
func (o *AuthorizationReverseParams) WithHTTPClient(client *http.Client) *AuthorizationReverseParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the authorization reverse params
func (o *AuthorizationReverseParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithReferenceNumber adds the referenceNumber to the authorization reverse params
func (o *AuthorizationReverseParams) WithReferenceNumber(referenceNumber string) *AuthorizationReverseParams {
	o.SetReferenceNumber(referenceNumber)
	return o
}

// SetReferenceNumber adds the referenceNumber to the authorization reverse params
func (o *AuthorizationReverseParams) SetReferenceNumber(referenceNumber string) {
	o.ReferenceNumber = referenceNumber
}

// WithReversalRequest adds the reversalRequest to the authorization reverse params
func (o *AuthorizationReverseParams) WithReversalRequest(reversalRequest *models.ReversalRequest) *AuthorizationReverseParams {
	o.SetReversalRequest(reversalRequest)
	return o
}

// SetReversalRequest adds the reversalRequest to the authorization reverse params
func (o *AuthorizationReverseParams) SetReversalRequest(reversalRequest *models.ReversalRequest) {
	o.ReversalRequest = reversalRequest
}

// WriteToRequest writes these params to a swagger request
func (o *AuthorizationReverseParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param referenceNumber
	if err := r.SetPathParam("referenceNumber", o.ReferenceNumber); err != nil {
		return err
	}
	if o.ReversalRequest != nil {
		if err := r.SetBodyParam(o.ReversalRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}