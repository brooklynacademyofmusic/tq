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

// NewAnalyticsReportsUpdateParams creates a new AnalyticsReportsUpdateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAnalyticsReportsUpdateParams() *AnalyticsReportsUpdateParams {
	return &AnalyticsReportsUpdateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAnalyticsReportsUpdateParamsWithTimeout creates a new AnalyticsReportsUpdateParams object
// with the ability to set a timeout on a request.
func NewAnalyticsReportsUpdateParamsWithTimeout(timeout time.Duration) *AnalyticsReportsUpdateParams {
	return &AnalyticsReportsUpdateParams{
		timeout: timeout,
	}
}

// NewAnalyticsReportsUpdateParamsWithContext creates a new AnalyticsReportsUpdateParams object
// with the ability to set a context for a request.
func NewAnalyticsReportsUpdateParamsWithContext(ctx context.Context) *AnalyticsReportsUpdateParams {
	return &AnalyticsReportsUpdateParams{
		Context: ctx,
	}
}

// NewAnalyticsReportsUpdateParamsWithHTTPClient creates a new AnalyticsReportsUpdateParams object
// with the ability to set a custom HTTPClient for a request.
func NewAnalyticsReportsUpdateParamsWithHTTPClient(client *http.Client) *AnalyticsReportsUpdateParams {
	return &AnalyticsReportsUpdateParams{
		HTTPClient: client,
	}
}

/*
AnalyticsReportsUpdateParams contains all the parameters to send to the API endpoint

	for the analytics reports update operation.

	Typically these are written to a http.Request.
*/
type AnalyticsReportsUpdateParams struct {

	// AnalyticsReport.
	AnalyticsReport *models.AnalyticsReport

	// AnalyticsReportID.
	AnalyticsReportID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the analytics reports update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AnalyticsReportsUpdateParams) WithDefaults() *AnalyticsReportsUpdateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the analytics reports update params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AnalyticsReportsUpdateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) WithTimeout(timeout time.Duration) *AnalyticsReportsUpdateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) WithContext(ctx context.Context) *AnalyticsReportsUpdateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) WithHTTPClient(client *http.Client) *AnalyticsReportsUpdateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAnalyticsReport adds the analyticsReport to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) WithAnalyticsReport(analyticsReport *models.AnalyticsReport) *AnalyticsReportsUpdateParams {
	o.SetAnalyticsReport(analyticsReport)
	return o
}

// SetAnalyticsReport adds the analyticsReport to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) SetAnalyticsReport(analyticsReport *models.AnalyticsReport) {
	o.AnalyticsReport = analyticsReport
}

// WithAnalyticsReportID adds the analyticsReportID to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) WithAnalyticsReportID(analyticsReportID string) *AnalyticsReportsUpdateParams {
	o.SetAnalyticsReportID(analyticsReportID)
	return o
}

// SetAnalyticsReportID adds the analyticsReportId to the analytics reports update params
func (o *AnalyticsReportsUpdateParams) SetAnalyticsReportID(analyticsReportID string) {
	o.AnalyticsReportID = analyticsReportID
}

// WriteToRequest writes these params to a swagger request
func (o *AnalyticsReportsUpdateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.AnalyticsReport != nil {
		if err := r.SetBodyParam(o.AnalyticsReport); err != nil {
			return err
		}
	}

	// path param analyticsReportId
	if err := r.SetPathParam("analyticsReportId", o.AnalyticsReportID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}