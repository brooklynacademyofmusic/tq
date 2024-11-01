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

// NewAssociationsDeleteParams creates a new AssociationsDeleteParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAssociationsDeleteParams() *AssociationsDeleteParams {
	return &AssociationsDeleteParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAssociationsDeleteParamsWithTimeout creates a new AssociationsDeleteParams object
// with the ability to set a timeout on a request.
func NewAssociationsDeleteParamsWithTimeout(timeout time.Duration) *AssociationsDeleteParams {
	return &AssociationsDeleteParams{
		timeout: timeout,
	}
}

// NewAssociationsDeleteParamsWithContext creates a new AssociationsDeleteParams object
// with the ability to set a context for a request.
func NewAssociationsDeleteParamsWithContext(ctx context.Context) *AssociationsDeleteParams {
	return &AssociationsDeleteParams{
		Context: ctx,
	}
}

// NewAssociationsDeleteParamsWithHTTPClient creates a new AssociationsDeleteParams object
// with the ability to set a custom HTTPClient for a request.
func NewAssociationsDeleteParamsWithHTTPClient(client *http.Client) *AssociationsDeleteParams {
	return &AssociationsDeleteParams{
		HTTPClient: client,
	}
}

/*
AssociationsDeleteParams contains all the parameters to send to the API endpoint

	for the associations delete operation.

	Typically these are written to a http.Request.
*/
type AssociationsDeleteParams struct {

	// AssociationID.
	AssociationID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the associations delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AssociationsDeleteParams) WithDefaults() *AssociationsDeleteParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the associations delete params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AssociationsDeleteParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the associations delete params
func (o *AssociationsDeleteParams) WithTimeout(timeout time.Duration) *AssociationsDeleteParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the associations delete params
func (o *AssociationsDeleteParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the associations delete params
func (o *AssociationsDeleteParams) WithContext(ctx context.Context) *AssociationsDeleteParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the associations delete params
func (o *AssociationsDeleteParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the associations delete params
func (o *AssociationsDeleteParams) WithHTTPClient(client *http.Client) *AssociationsDeleteParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the associations delete params
func (o *AssociationsDeleteParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAssociationID adds the associationID to the associations delete params
func (o *AssociationsDeleteParams) WithAssociationID(associationID string) *AssociationsDeleteParams {
	o.SetAssociationID(associationID)
	return o
}

// SetAssociationID adds the associationId to the associations delete params
func (o *AssociationsDeleteParams) SetAssociationID(associationID string) {
	o.AssociationID = associationID
}

// WriteToRequest writes these params to a swagger request
func (o *AssociationsDeleteParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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