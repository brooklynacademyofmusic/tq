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

// NewOrderCategoriesGetParams creates a new OrderCategoriesGetParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOrderCategoriesGetParams() *OrderCategoriesGetParams {
	return &OrderCategoriesGetParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOrderCategoriesGetParamsWithTimeout creates a new OrderCategoriesGetParams object
// with the ability to set a timeout on a request.
func NewOrderCategoriesGetParamsWithTimeout(timeout time.Duration) *OrderCategoriesGetParams {
	return &OrderCategoriesGetParams{
		timeout: timeout,
	}
}

// NewOrderCategoriesGetParamsWithContext creates a new OrderCategoriesGetParams object
// with the ability to set a context for a request.
func NewOrderCategoriesGetParamsWithContext(ctx context.Context) *OrderCategoriesGetParams {
	return &OrderCategoriesGetParams{
		Context: ctx,
	}
}

// NewOrderCategoriesGetParamsWithHTTPClient creates a new OrderCategoriesGetParams object
// with the ability to set a custom HTTPClient for a request.
func NewOrderCategoriesGetParamsWithHTTPClient(client *http.Client) *OrderCategoriesGetParams {
	return &OrderCategoriesGetParams{
		HTTPClient: client,
	}
}

/*
OrderCategoriesGetParams contains all the parameters to send to the API endpoint

	for the order categories get operation.

	Typically these are written to a http.Request.
*/
type OrderCategoriesGetParams struct {

	// ID.
	ID string

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the order categories get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OrderCategoriesGetParams) WithDefaults() *OrderCategoriesGetParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the order categories get params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OrderCategoriesGetParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the order categories get params
func (o *OrderCategoriesGetParams) WithTimeout(timeout time.Duration) *OrderCategoriesGetParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the order categories get params
func (o *OrderCategoriesGetParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the order categories get params
func (o *OrderCategoriesGetParams) WithContext(ctx context.Context) *OrderCategoriesGetParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the order categories get params
func (o *OrderCategoriesGetParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the order categories get params
func (o *OrderCategoriesGetParams) WithHTTPClient(client *http.Client) *OrderCategoriesGetParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the order categories get params
func (o *OrderCategoriesGetParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the order categories get params
func (o *OrderCategoriesGetParams) WithID(id string) *OrderCategoriesGetParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the order categories get params
func (o *OrderCategoriesGetParams) SetID(id string) {
	o.ID = id
}

// WithMaintenanceMode adds the maintenanceMode to the order categories get params
func (o *OrderCategoriesGetParams) WithMaintenanceMode(maintenanceMode *string) *OrderCategoriesGetParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the order categories get params
func (o *OrderCategoriesGetParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *OrderCategoriesGetParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if o.MaintenanceMode != nil {

		// query param maintenanceMode
		var qrMaintenanceMode string

		if o.MaintenanceMode != nil {
			qrMaintenanceMode = *o.MaintenanceMode
		}
		qMaintenanceMode := qrMaintenanceMode
		if qMaintenanceMode != "" {

			if err := r.SetQueryParam("maintenanceMode", qMaintenanceMode); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}