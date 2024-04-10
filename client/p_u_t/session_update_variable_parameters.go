// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

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

// NewSessionUpdateVariableParams creates a new SessionUpdateVariableParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewSessionUpdateVariableParams() *SessionUpdateVariableParams {
	return &SessionUpdateVariableParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewSessionUpdateVariableParamsWithTimeout creates a new SessionUpdateVariableParams object
// with the ability to set a timeout on a request.
func NewSessionUpdateVariableParamsWithTimeout(timeout time.Duration) *SessionUpdateVariableParams {
	return &SessionUpdateVariableParams{
		timeout: timeout,
	}
}

// NewSessionUpdateVariableParamsWithContext creates a new SessionUpdateVariableParams object
// with the ability to set a context for a request.
func NewSessionUpdateVariableParamsWithContext(ctx context.Context) *SessionUpdateVariableParams {
	return &SessionUpdateVariableParams{
		Context: ctx,
	}
}

// NewSessionUpdateVariableParamsWithHTTPClient creates a new SessionUpdateVariableParams object
// with the ability to set a custom HTTPClient for a request.
func NewSessionUpdateVariableParamsWithHTTPClient(client *http.Client) *SessionUpdateVariableParams {
	return &SessionUpdateVariableParams{
		HTTPClient: client,
	}
}

/*
SessionUpdateVariableParams contains all the parameters to send to the API endpoint

	for the session update variable operation.

	Typically these are written to a http.Request.
*/
type SessionUpdateVariableParams struct {

	// SessionKey.
	SessionKey string

	// SessionVariable.
	SessionVariable *models.SessionVariable

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the session update variable params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SessionUpdateVariableParams) WithDefaults() *SessionUpdateVariableParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the session update variable params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *SessionUpdateVariableParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the session update variable params
func (o *SessionUpdateVariableParams) WithTimeout(timeout time.Duration) *SessionUpdateVariableParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the session update variable params
func (o *SessionUpdateVariableParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the session update variable params
func (o *SessionUpdateVariableParams) WithContext(ctx context.Context) *SessionUpdateVariableParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the session update variable params
func (o *SessionUpdateVariableParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the session update variable params
func (o *SessionUpdateVariableParams) WithHTTPClient(client *http.Client) *SessionUpdateVariableParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the session update variable params
func (o *SessionUpdateVariableParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSessionKey adds the sessionKey to the session update variable params
func (o *SessionUpdateVariableParams) WithSessionKey(sessionKey string) *SessionUpdateVariableParams {
	o.SetSessionKey(sessionKey)
	return o
}

// SetSessionKey adds the sessionKey to the session update variable params
func (o *SessionUpdateVariableParams) SetSessionKey(sessionKey string) {
	o.SessionKey = sessionKey
}

// WithSessionVariable adds the sessionVariable to the session update variable params
func (o *SessionUpdateVariableParams) WithSessionVariable(sessionVariable *models.SessionVariable) *SessionUpdateVariableParams {
	o.SetSessionVariable(sessionVariable)
	return o
}

// SetSessionVariable adds the sessionVariable to the session update variable params
func (o *SessionUpdateVariableParams) SetSessionVariable(sessionVariable *models.SessionVariable) {
	o.SessionVariable = sessionVariable
}

// WriteToRequest writes these params to a swagger request
func (o *SessionUpdateVariableParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param sessionKey
	if err := r.SetPathParam("sessionKey", o.SessionKey); err != nil {
		return err
	}
	if o.SessionVariable != nil {
		if err := r.SetBodyParam(o.SessionVariable); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}