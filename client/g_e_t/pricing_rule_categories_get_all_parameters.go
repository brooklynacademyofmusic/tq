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

// NewPricingRuleCategoriesGetAllParams creates a new PricingRuleCategoriesGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPricingRuleCategoriesGetAllParams() *PricingRuleCategoriesGetAllParams {
	return &PricingRuleCategoriesGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPricingRuleCategoriesGetAllParamsWithTimeout creates a new PricingRuleCategoriesGetAllParams object
// with the ability to set a timeout on a request.
func NewPricingRuleCategoriesGetAllParamsWithTimeout(timeout time.Duration) *PricingRuleCategoriesGetAllParams {
	return &PricingRuleCategoriesGetAllParams{
		timeout: timeout,
	}
}

// NewPricingRuleCategoriesGetAllParamsWithContext creates a new PricingRuleCategoriesGetAllParams object
// with the ability to set a context for a request.
func NewPricingRuleCategoriesGetAllParamsWithContext(ctx context.Context) *PricingRuleCategoriesGetAllParams {
	return &PricingRuleCategoriesGetAllParams{
		Context: ctx,
	}
}

// NewPricingRuleCategoriesGetAllParamsWithHTTPClient creates a new PricingRuleCategoriesGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewPricingRuleCategoriesGetAllParamsWithHTTPClient(client *http.Client) *PricingRuleCategoriesGetAllParams {
	return &PricingRuleCategoriesGetAllParams{
		HTTPClient: client,
	}
}

/*
PricingRuleCategoriesGetAllParams contains all the parameters to send to the API endpoint

	for the pricing rule categories get all operation.

	Typically these are written to a http.Request.
*/
type PricingRuleCategoriesGetAllParams struct {

	/* Filter.

	   Filter by user access (default: readwrite)
	*/
	Filter *string

	/* MaintenanceMode.

	   Ignore control grouping (default: false)
	*/
	MaintenanceMode *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the pricing rule categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PricingRuleCategoriesGetAllParams) WithDefaults() *PricingRuleCategoriesGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the pricing rule categories get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PricingRuleCategoriesGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) WithTimeout(timeout time.Duration) *PricingRuleCategoriesGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) WithContext(ctx context.Context) *PricingRuleCategoriesGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) WithHTTPClient(client *http.Client) *PricingRuleCategoriesGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFilter adds the filter to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) WithFilter(filter *string) *PricingRuleCategoriesGetAllParams {
	o.SetFilter(filter)
	return o
}

// SetFilter adds the filter to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) SetFilter(filter *string) {
	o.Filter = filter
}

// WithMaintenanceMode adds the maintenanceMode to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) WithMaintenanceMode(maintenanceMode *string) *PricingRuleCategoriesGetAllParams {
	o.SetMaintenanceMode(maintenanceMode)
	return o
}

// SetMaintenanceMode adds the maintenanceMode to the pricing rule categories get all params
func (o *PricingRuleCategoriesGetAllParams) SetMaintenanceMode(maintenanceMode *string) {
	o.MaintenanceMode = maintenanceMode
}

// WriteToRequest writes these params to a swagger request
func (o *PricingRuleCategoriesGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Filter != nil {

		// query param filter
		var qrFilter string

		if o.Filter != nil {
			qrFilter = *o.Filter
		}
		qFilter := qrFilter
		if qFilter != "" {

			if err := r.SetQueryParam("filter", qFilter); err != nil {
				return err
			}
		}
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