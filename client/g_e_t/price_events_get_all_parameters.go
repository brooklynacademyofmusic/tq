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

// NewPriceEventsGetAllParams creates a new PriceEventsGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPriceEventsGetAllParams() *PriceEventsGetAllParams {
	return &PriceEventsGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPriceEventsGetAllParamsWithTimeout creates a new PriceEventsGetAllParams object
// with the ability to set a timeout on a request.
func NewPriceEventsGetAllParamsWithTimeout(timeout time.Duration) *PriceEventsGetAllParams {
	return &PriceEventsGetAllParams{
		timeout: timeout,
	}
}

// NewPriceEventsGetAllParamsWithContext creates a new PriceEventsGetAllParams object
// with the ability to set a context for a request.
func NewPriceEventsGetAllParamsWithContext(ctx context.Context) *PriceEventsGetAllParams {
	return &PriceEventsGetAllParams{
		Context: ctx,
	}
}

// NewPriceEventsGetAllParamsWithHTTPClient creates a new PriceEventsGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewPriceEventsGetAllParamsWithHTTPClient(client *http.Client) *PriceEventsGetAllParams {
	return &PriceEventsGetAllParams{
		HTTPClient: client,
	}
}

/*
PriceEventsGetAllParams contains all the parameters to send to the API endpoint

	for the price events get all operation.

	Typically these are written to a http.Request.
*/
type PriceEventsGetAllParams struct {

	// FromDate.
	FromDate *string

	// PerformanceIds.
	PerformanceIds *string

	// PerformancePriceIds.
	PerformancePriceIds *string

	// PerformancePriceLayerIds.
	PerformancePriceLayerIds *string

	// PerformancePriceTypeIds.
	PerformancePriceTypeIds *string

	// ToDate.
	ToDate *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the price events get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceEventsGetAllParams) WithDefaults() *PriceEventsGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the price events get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PriceEventsGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the price events get all params
func (o *PriceEventsGetAllParams) WithTimeout(timeout time.Duration) *PriceEventsGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the price events get all params
func (o *PriceEventsGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the price events get all params
func (o *PriceEventsGetAllParams) WithContext(ctx context.Context) *PriceEventsGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the price events get all params
func (o *PriceEventsGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the price events get all params
func (o *PriceEventsGetAllParams) WithHTTPClient(client *http.Client) *PriceEventsGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the price events get all params
func (o *PriceEventsGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithFromDate adds the fromDate to the price events get all params
func (o *PriceEventsGetAllParams) WithFromDate(fromDate *string) *PriceEventsGetAllParams {
	o.SetFromDate(fromDate)
	return o
}

// SetFromDate adds the fromDate to the price events get all params
func (o *PriceEventsGetAllParams) SetFromDate(fromDate *string) {
	o.FromDate = fromDate
}

// WithPerformanceIds adds the performanceIds to the price events get all params
func (o *PriceEventsGetAllParams) WithPerformanceIds(performanceIds *string) *PriceEventsGetAllParams {
	o.SetPerformanceIds(performanceIds)
	return o
}

// SetPerformanceIds adds the performanceIds to the price events get all params
func (o *PriceEventsGetAllParams) SetPerformanceIds(performanceIds *string) {
	o.PerformanceIds = performanceIds
}

// WithPerformancePriceIds adds the performancePriceIds to the price events get all params
func (o *PriceEventsGetAllParams) WithPerformancePriceIds(performancePriceIds *string) *PriceEventsGetAllParams {
	o.SetPerformancePriceIds(performancePriceIds)
	return o
}

// SetPerformancePriceIds adds the performancePriceIds to the price events get all params
func (o *PriceEventsGetAllParams) SetPerformancePriceIds(performancePriceIds *string) {
	o.PerformancePriceIds = performancePriceIds
}

// WithPerformancePriceLayerIds adds the performancePriceLayerIds to the price events get all params
func (o *PriceEventsGetAllParams) WithPerformancePriceLayerIds(performancePriceLayerIds *string) *PriceEventsGetAllParams {
	o.SetPerformancePriceLayerIds(performancePriceLayerIds)
	return o
}

// SetPerformancePriceLayerIds adds the performancePriceLayerIds to the price events get all params
func (o *PriceEventsGetAllParams) SetPerformancePriceLayerIds(performancePriceLayerIds *string) {
	o.PerformancePriceLayerIds = performancePriceLayerIds
}

// WithPerformancePriceTypeIds adds the performancePriceTypeIds to the price events get all params
func (o *PriceEventsGetAllParams) WithPerformancePriceTypeIds(performancePriceTypeIds *string) *PriceEventsGetAllParams {
	o.SetPerformancePriceTypeIds(performancePriceTypeIds)
	return o
}

// SetPerformancePriceTypeIds adds the performancePriceTypeIds to the price events get all params
func (o *PriceEventsGetAllParams) SetPerformancePriceTypeIds(performancePriceTypeIds *string) {
	o.PerformancePriceTypeIds = performancePriceTypeIds
}

// WithToDate adds the toDate to the price events get all params
func (o *PriceEventsGetAllParams) WithToDate(toDate *string) *PriceEventsGetAllParams {
	o.SetToDate(toDate)
	return o
}

// SetToDate adds the toDate to the price events get all params
func (o *PriceEventsGetAllParams) SetToDate(toDate *string) {
	o.ToDate = toDate
}

// WriteToRequest writes these params to a swagger request
func (o *PriceEventsGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.FromDate != nil {

		// query param fromDate
		var qrFromDate string

		if o.FromDate != nil {
			qrFromDate = *o.FromDate
		}
		qFromDate := qrFromDate
		if qFromDate != "" {

			if err := r.SetQueryParam("fromDate", qFromDate); err != nil {
				return err
			}
		}
	}

	if o.PerformanceIds != nil {

		// query param performanceIds
		var qrPerformanceIds string

		if o.PerformanceIds != nil {
			qrPerformanceIds = *o.PerformanceIds
		}
		qPerformanceIds := qrPerformanceIds
		if qPerformanceIds != "" {

			if err := r.SetQueryParam("performanceIds", qPerformanceIds); err != nil {
				return err
			}
		}
	}

	if o.PerformancePriceIds != nil {

		// query param performancePriceIds
		var qrPerformancePriceIds string

		if o.PerformancePriceIds != nil {
			qrPerformancePriceIds = *o.PerformancePriceIds
		}
		qPerformancePriceIds := qrPerformancePriceIds
		if qPerformancePriceIds != "" {

			if err := r.SetQueryParam("performancePriceIds", qPerformancePriceIds); err != nil {
				return err
			}
		}
	}

	if o.PerformancePriceLayerIds != nil {

		// query param performancePriceLayerIds
		var qrPerformancePriceLayerIds string

		if o.PerformancePriceLayerIds != nil {
			qrPerformancePriceLayerIds = *o.PerformancePriceLayerIds
		}
		qPerformancePriceLayerIds := qrPerformancePriceLayerIds
		if qPerformancePriceLayerIds != "" {

			if err := r.SetQueryParam("performancePriceLayerIds", qPerformancePriceLayerIds); err != nil {
				return err
			}
		}
	}

	if o.PerformancePriceTypeIds != nil {

		// query param performancePriceTypeIds
		var qrPerformancePriceTypeIds string

		if o.PerformancePriceTypeIds != nil {
			qrPerformancePriceTypeIds = *o.PerformancePriceTypeIds
		}
		qPerformancePriceTypeIds := qrPerformancePriceTypeIds
		if qPerformancePriceTypeIds != "" {

			if err := r.SetQueryParam("performancePriceTypeIds", qPerformancePriceTypeIds); err != nil {
				return err
			}
		}
	}

	if o.ToDate != nil {

		// query param toDate
		var qrToDate string

		if o.ToDate != nil {
			qrToDate = *o.ToDate
		}
		qToDate := qrToDate
		if qToDate != "" {

			if err := r.SetQueryParam("toDate", qToDate); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}