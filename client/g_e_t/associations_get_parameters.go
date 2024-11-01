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

// NewAssociationsGetParams creates a new AssociationsGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAssociationsGetParams() *AssociationsGetParams {
	return &AssociationsGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAssociationsGetParamsWithTimeout creates a new AssociationsGetParams object
// with the ability to set a timeout on a request.
func NewAssociationsGetParamsWithTimeout(timeout time.Duration) *AssociationsGetParams {
	return &AssociationsGetParams{
		timeout: timeout,
	}
}

// NewAssociationsGetParamsWithContext creates a new AssociationsGetParams object
// with the ability to set a context for a request.
func NewAssociationsGetParamsWithContext(ctx context.Context) *AssociationsGetParams {
	return &AssociationsGetParams{
		Context: ctx,
	}
}

// NewAssociationsGetParamsWithHTTPClient creates a new AssociationsGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewAssociationsGetParamsWithHTTPClient(client *http.Client) *AssociationsGetParams {
	return &AssociationsGetParams{
		HTTPClient: client,
	}
}

/*
AssociationsGetParams contains all the parameters to send to the API endpoint

	for the associations get operation.

	Typically these are written to a http.Request.
*/
type AssociationsGetParams struct {

	// AssociationID.
	AssociationID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the associations get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AssociationsGetParams) WithDefaults() *AssociationsGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the associations get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AssociationsGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the associations get params
func (o *AssociationsGetParams) WithTimeout(timeout time.Duration) *AssociationsGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the associations get params
func (o *AssociationsGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the associations get params
func (o *AssociationsGetParams) WithContext(ctx context.Context) *AssociationsGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the associations get params
func (o *AssociationsGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the associations get params
func (o *AssociationsGetParams) WithHTTPClient(client *http.Client) *AssociationsGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the associations get params
func (o *AssociationsGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssociationID adds the associationID to the associations get params
func (o *AssociationsGetParams) WithAssociationID(associationID string) *AssociationsGetParams {
	o.SetAssociationID(associationID)
	return o
}

// SetAssociationID adds the associationId to the associations get params
func (o *AssociationsGetParams) SetAssociationID(associationID string) {
	o.AssociationID = associationID
}

// WriteToRequest writes these params to a swagger request
func (o *AssociationsGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param associationId
	if err := r.SetPathParam("associationId", o.AssociationID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}