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

// NewResourceSchedulesCreateParams creates a new ResourceSchedulesCreateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewResourceSchedulesCreateParams() *ResourceSchedulesCreateParams {
	return &ResourceSchedulesCreateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewResourceSchedulesCreateParamsWithTimeout creates a new ResourceSchedulesCreateParams object
// with the ability to set a timeout on a request.
func NewResourceSchedulesCreateParamsWithTimeout(timeout time.Duration) *ResourceSchedulesCreateParams {
	return &ResourceSchedulesCreateParams{
		timeout: timeout,
	}
}

// NewResourceSchedulesCreateParamsWithContext creates a new ResourceSchedulesCreateParams object
// with the ability to set a context for a request.
func NewResourceSchedulesCreateParamsWithContext(ctx context.Context) *ResourceSchedulesCreateParams {
	return &ResourceSchedulesCreateParams{
		Context: ctx,
	}
}

// NewResourceSchedulesCreateParamsWithHTTPClient creates a new ResourceSchedulesCreateParams object
// with the ability to set a custom HTTPClient for a request.
func NewResourceSchedulesCreateParamsWithHTTPClient(client *http.Client) *ResourceSchedulesCreateParams {
	return &ResourceSchedulesCreateParams{
		HTTPClient: client,
	}
}

/*
ResourceSchedulesCreateParams contains all the parameters to send to the API endpoint

	for the resource schedules create operation.

	Typically these are written to a http.Request.
*/
type ResourceSchedulesCreateParams struct {

	// ResourceSchedule.
	ResourceSchedule *models.ResourceSchedule

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the resource schedules create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResourceSchedulesCreateParams) WithDefaults() *ResourceSchedulesCreateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the resource schedules create params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ResourceSchedulesCreateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the resource schedules create params
func (o *ResourceSchedulesCreateParams) WithTimeout(timeout time.Duration) *ResourceSchedulesCreateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the resource schedules create params
func (o *ResourceSchedulesCreateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the resource schedules create params
func (o *ResourceSchedulesCreateParams) WithContext(ctx context.Context) *ResourceSchedulesCreateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the resource schedules create params
func (o *ResourceSchedulesCreateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the resource schedules create params
func (o *ResourceSchedulesCreateParams) WithHTTPClient(client *http.Client) *ResourceSchedulesCreateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the resource schedules create params
func (o *ResourceSchedulesCreateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithResourceSchedule adds the resourceSchedule to the resource schedules create params
func (o *ResourceSchedulesCreateParams) WithResourceSchedule(resourceSchedule *models.ResourceSchedule) *ResourceSchedulesCreateParams {
	o.SetResourceSchedule(resourceSchedule)
	return o
}

// SetResourceSchedule adds the resourceSchedule to the resource schedules create params
func (o *ResourceSchedulesCreateParams) SetResourceSchedule(resourceSchedule *models.ResourceSchedule) {
	o.ResourceSchedule = resourceSchedule
}

// WriteToRequest writes these params to a swagger request
func (o *ResourceSchedulesCreateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.ResourceSchedule != nil {
		if err := r.SetBodyParam(o.ResourceSchedule); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}