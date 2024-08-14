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

// NewQueryElementFiltersGetAllParams creates a new QueryElementFiltersGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewQueryElementFiltersGetAllParams() *QueryElementFiltersGetAllParams {
	return &QueryElementFiltersGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewQueryElementFiltersGetAllParamsWithTimeout creates a new QueryElementFiltersGetAllParams object
// with the ability to set a timeout on a request.
func NewQueryElementFiltersGetAllParamsWithTimeout(timeout time.Duration) *QueryElementFiltersGetAllParams {
	return &QueryElementFiltersGetAllParams{
		timeout: timeout,
	}
}

// NewQueryElementFiltersGetAllParamsWithContext creates a new QueryElementFiltersGetAllParams object
// with the ability to set a context for a request.
func NewQueryElementFiltersGetAllParamsWithContext(ctx context.Context) *QueryElementFiltersGetAllParams {
	return &QueryElementFiltersGetAllParams{
		Context: ctx,
	}
}

// NewQueryElementFiltersGetAllParamsWithHTTPClient creates a new QueryElementFiltersGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewQueryElementFiltersGetAllParamsWithHTTPClient(client *http.Client) *QueryElementFiltersGetAllParams {
	return &QueryElementFiltersGetAllParams{
		HTTPClient: client,
	}
}

/*
QueryElementFiltersGetAllParams contains all the parameters to send to the API endpoint

	for the query element filters get all operation.

	Typically these are written to a http.Request.
*/
type QueryElementFiltersGetAllParams struct {

	// GroupIds.
	GroupIds *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the query element filters get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryElementFiltersGetAllParams) WithDefaults() *QueryElementFiltersGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the query element filters get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *QueryElementFiltersGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) WithTimeout(timeout time.Duration) *QueryElementFiltersGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) WithContext(ctx context.Context) *QueryElementFiltersGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) WithHTTPClient(client *http.Client) *QueryElementFiltersGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithGroupIds adds the groupIds to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) WithGroupIds(groupIds *string) *QueryElementFiltersGetAllParams {
	o.SetGroupIds(groupIds)
	return o
}

// SetGroupIds adds the groupIds to the query element filters get all params
func (o *QueryElementFiltersGetAllParams) SetGroupIds(groupIds *string) {
	o.GroupIds = groupIds
}

// WriteToRequest writes these params to a swagger request
func (o *QueryElementFiltersGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.GroupIds != nil {

		// query param groupIds
		var qrGroupIds string

		if o.GroupIds != nil {
			qrGroupIds = *o.GroupIds
		}
		qGroupIds := qrGroupIds
		if qGroupIds != "" {

			if err := r.SetQueryParam("groupIds", qGroupIds); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}