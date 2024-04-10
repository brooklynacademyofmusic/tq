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

// NewEMVAuthorizationParams creates a new EMVAuthorizationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewEMVAuthorizationParams() *EMVAuthorizationParams {
	return &EMVAuthorizationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewEMVAuthorizationParamsWithTimeout creates a new EMVAuthorizationParams object
// with the ability to set a timeout on a request.
func NewEMVAuthorizationParamsWithTimeout(timeout time.Duration) *EMVAuthorizationParams {
	return &EMVAuthorizationParams{
		timeout: timeout,
	}
}

// NewEMVAuthorizationParamsWithContext creates a new EMVAuthorizationParams object
// with the ability to set a context for a request.
func NewEMVAuthorizationParamsWithContext(ctx context.Context) *EMVAuthorizationParams {
	return &EMVAuthorizationParams{
		Context: ctx,
	}
}

// NewEMVAuthorizationParamsWithHTTPClient creates a new EMVAuthorizationParams object
// with the ability to set a custom HTTPClient for a request.
func NewEMVAuthorizationParamsWithHTTPClient(client *http.Client) *EMVAuthorizationParams {
	return &EMVAuthorizationParams{
		HTTPClient: client,
	}
}

/*
EMVAuthorizationParams contains all the parameters to send to the API endpoint

	for the e m v authorization operation.

	Typically these are written to a http.Request.
*/
type EMVAuthorizationParams struct {

	// Request.
	Request *models.EMVAuthorizationRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the e m v authorization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EMVAuthorizationParams) WithDefaults() *EMVAuthorizationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the e m v authorization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EMVAuthorizationParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the e m v authorization params
func (o *EMVAuthorizationParams) WithTimeout(timeout time.Duration) *EMVAuthorizationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the e m v authorization params
func (o *EMVAuthorizationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the e m v authorization params
func (o *EMVAuthorizationParams) WithContext(ctx context.Context) *EMVAuthorizationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the e m v authorization params
func (o *EMVAuthorizationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the e m v authorization params
func (o *EMVAuthorizationParams) WithHTTPClient(client *http.Client) *EMVAuthorizationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the e m v authorization params
func (o *EMVAuthorizationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the e m v authorization params
func (o *EMVAuthorizationParams) WithRequest(request *models.EMVAuthorizationRequest) *EMVAuthorizationParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the e m v authorization params
func (o *EMVAuthorizationParams) SetRequest(request *models.EMVAuthorizationRequest) {
	o.Request = request
}

// WriteToRequest writes these params to a swagger request
func (o *EMVAuthorizationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Request != nil {
		if err := r.SetBodyParam(o.Request); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}