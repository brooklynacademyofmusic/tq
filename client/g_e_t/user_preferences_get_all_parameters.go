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

// NewUserPreferencesGetAllParams creates a new UserPreferencesGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewUserPreferencesGetAllParams() *UserPreferencesGetAllParams {
	return &UserPreferencesGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewUserPreferencesGetAllParamsWithTimeout creates a new UserPreferencesGetAllParams object
// with the ability to set a timeout on a request.
func NewUserPreferencesGetAllParamsWithTimeout(timeout time.Duration) *UserPreferencesGetAllParams {
	return &UserPreferencesGetAllParams{
		timeout: timeout,
	}
}

// NewUserPreferencesGetAllParamsWithContext creates a new UserPreferencesGetAllParams object
// with the ability to set a context for a request.
func NewUserPreferencesGetAllParamsWithContext(ctx context.Context) *UserPreferencesGetAllParams {
	return &UserPreferencesGetAllParams{
		Context: ctx,
	}
}

// NewUserPreferencesGetAllParamsWithHTTPClient creates a new UserPreferencesGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewUserPreferencesGetAllParamsWithHTTPClient(client *http.Client) *UserPreferencesGetAllParams {
	return &UserPreferencesGetAllParams{
		HTTPClient: client,
	}
}

/*
UserPreferencesGetAllParams contains all the parameters to send to the API endpoint

	for the user preferences get all operation.

	Typically these are written to a http.Request.
*/
type UserPreferencesGetAllParams struct {

	/* Keys.

	   A comma separated list.
	*/
	Keys *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the user preferences get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UserPreferencesGetAllParams) WithDefaults() *UserPreferencesGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the user preferences get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *UserPreferencesGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the user preferences get all params
func (o *UserPreferencesGetAllParams) WithTimeout(timeout time.Duration) *UserPreferencesGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the user preferences get all params
func (o *UserPreferencesGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the user preferences get all params
func (o *UserPreferencesGetAllParams) WithContext(ctx context.Context) *UserPreferencesGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the user preferences get all params
func (o *UserPreferencesGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the user preferences get all params
func (o *UserPreferencesGetAllParams) WithHTTPClient(client *http.Client) *UserPreferencesGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the user preferences get all params
func (o *UserPreferencesGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithKeys adds the keys to the user preferences get all params
func (o *UserPreferencesGetAllParams) WithKeys(keys *string) *UserPreferencesGetAllParams {
	o.SetKeys(keys)
	return o
}

// SetKeys adds the keys to the user preferences get all params
func (o *UserPreferencesGetAllParams) SetKeys(keys *string) {
	o.Keys = keys
}

// WriteToRequest writes these params to a swagger request
func (o *UserPreferencesGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Keys != nil {

		// query param keys
		var qrKeys string

		if o.Keys != nil {
			qrKeys = *o.Keys
		}
		qKeys := qrKeys
		if qKeys != "" {

			if err := r.SetQueryParam("keys", qKeys); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}