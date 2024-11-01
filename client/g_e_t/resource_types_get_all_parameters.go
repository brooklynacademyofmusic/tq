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

// NewResourceTypesGetAllParams creates a new ResourceTypesGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewResourceTypesGetAllParams() *ResourceTypesGetAllParams {
	return &ResourceTypesGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewResourceTypesGetAllParamsWithTimeout creates a new ResourceTypesGetAllParams object
// with the ability to set a timeout on a request.
func NewResourceTypesGetAllParamsWithTimeout(timeout time.Duration) *ResourceTypesGetAllParams {
	return &ResourceTypesGetAllParams{
		timeout: timeout,
	}
}

// NewResourceTypesGetAllParamsWithContext creates a new ResourceTypesGetAllParams object
// with the ability to set a context for a request.
func NewResourceTypesGetAllParamsWithContext(ctx context.Context) *ResourceTypesGetAllParams {
	return &ResourceTypesGetAllParams{
		Context: ctx,
	}
}

// NewResourceTypesGetAllParamsWithHTTPClient creates a new ResourceTypesGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewResourceTypesGetAllParamsWithHTTPClient(client *http.Client) *ResourceTypesGetAllParams {
	return &ResourceTypesGetAllParams{
		HTTPClient: client,
	}
}

/*
ResourceTypesGetAllParams contains all the parameters to send to the API endpoint

	for the resource types get all operation.

	Typically these are written to a http.Request.
*/
type ResourceTypesGetAllParams struct {

	// CategoryIds.
	CategoryIds *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the resource types get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResourceTypesGetAllParams) WithDefaults() *ResourceTypesGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the resource types get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResourceTypesGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the resource types get all params
func (o *ResourceTypesGetAllParams) WithTimeout(timeout time.Duration) *ResourceTypesGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the resource types get all params
func (o *ResourceTypesGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the resource types get all params
func (o *ResourceTypesGetAllParams) WithContext(ctx context.Context) *ResourceTypesGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the resource types get all params
func (o *ResourceTypesGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the resource types get all params
func (o *ResourceTypesGetAllParams) WithHTTPClient(client *http.Client) *ResourceTypesGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the resource types get all params
func (o *ResourceTypesGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCategoryIds adds the categoryIds to the resource types get all params
func (o *ResourceTypesGetAllParams) WithCategoryIds(categoryIds *string) *ResourceTypesGetAllParams {
	o.SetCategoryIds(categoryIds)
	return o
}

// SetCategoryIds adds the categoryIds to the resource types get all params
func (o *ResourceTypesGetAllParams) SetCategoryIds(categoryIds *string) {
	o.CategoryIds = categoryIds
}

// WriteToRequest writes these params to a swagger request
func (o *ResourceTypesGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.CategoryIds != nil {

		// query param categoryIds
		var qrCategoryIds string

		if o.CategoryIds != nil {
			qrCategoryIds = *o.CategoryIds
		}
		qCategoryIds := qrCategoryIds
		if qCategoryIds != "" {

			if err := r.SetQueryParam("categoryIds", qCategoryIds); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}