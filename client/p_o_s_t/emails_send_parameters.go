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

// NewEmailsSendParams creates a new EmailsSendParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewEmailsSendParams() *EmailsSendParams {
	return &EmailsSendParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewEmailsSendParamsWithTimeout creates a new EmailsSendParams object
// with the ability to set a timeout on a request.
func NewEmailsSendParamsWithTimeout(timeout time.Duration) *EmailsSendParams {
	return &EmailsSendParams{
		timeout: timeout,
	}
}

// NewEmailsSendParamsWithContext creates a new EmailsSendParams object
// with the ability to set a context for a request.
func NewEmailsSendParamsWithContext(ctx context.Context) *EmailsSendParams {
	return &EmailsSendParams{
		Context: ctx,
	}
}

// NewEmailsSendParamsWithHTTPClient creates a new EmailsSendParams object
// with the ability to set a custom HTTPClient for a request.
func NewEmailsSendParamsWithHTTPClient(client *http.Client) *EmailsSendParams {
	return &EmailsSendParams{
		HTTPClient: client,
	}
}

/*
EmailsSendParams contains all the parameters to send to the API endpoint

	for the emails send operation.

	Typically these are written to a http.Request.
*/
type EmailsSendParams struct {

	// Request.
	Request *models.EmailSendRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the emails send params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EmailsSendParams) WithDefaults() *EmailsSendParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the emails send params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EmailsSendParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the emails send params
func (o *EmailsSendParams) WithTimeout(timeout time.Duration) *EmailsSendParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the emails send params
func (o *EmailsSendParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the emails send params
func (o *EmailsSendParams) WithContext(ctx context.Context) *EmailsSendParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the emails send params
func (o *EmailsSendParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the emails send params
func (o *EmailsSendParams) WithHTTPClient(client *http.Client) *EmailsSendParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the emails send params
func (o *EmailsSendParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithRequest adds the request to the emails send params
func (o *EmailsSendParams) WithRequest(request *models.EmailSendRequest) *EmailsSendParams {
	o.SetRequest(request)
	return o
}

// SetRequest adds the request to the emails send params
func (o *EmailsSendParams) SetRequest(request *models.EmailSendRequest) {
	o.Request = request
}

// WriteToRequest writes these params to a swagger request
func (o *EmailsSendParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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