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

// NewReportsGetReportParametersParams creates a new ReportsGetReportParametersParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewReportsGetReportParametersParams() *ReportsGetReportParametersParams {
	return &ReportsGetReportParametersParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewReportsGetReportParametersParamsWithTimeout creates a new ReportsGetReportParametersParams object
// with the ability to set a timeout on a request.
func NewReportsGetReportParametersParamsWithTimeout(timeout time.Duration) *ReportsGetReportParametersParams {
	return &ReportsGetReportParametersParams{
		timeout: timeout,
	}
}

// NewReportsGetReportParametersParamsWithContext creates a new ReportsGetReportParametersParams object
// with the ability to set a context for a request.
func NewReportsGetReportParametersParamsWithContext(ctx context.Context) *ReportsGetReportParametersParams {
	return &ReportsGetReportParametersParams{
		Context: ctx,
	}
}

// NewReportsGetReportParametersParamsWithHTTPClient creates a new ReportsGetReportParametersParams object
// with the ability to set a custom HTTPClient for a request.
func NewReportsGetReportParametersParamsWithHTTPClient(client *http.Client) *ReportsGetReportParametersParams {
	return &ReportsGetReportParametersParams{
		HTTPClient: client,
	}
}

/*
ReportsGetReportParametersParams contains all the parameters to send to the API endpoint

	for the reports get report parameters operation.

	Typically these are written to a http.Request.
*/
type ReportsGetReportParametersParams struct {

	// ReportID.
	ReportID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the reports get report parameters params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReportsGetReportParametersParams) WithDefaults() *ReportsGetReportParametersParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the reports get report parameters params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ReportsGetReportParametersParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the reports get report parameters params
func (o *ReportsGetReportParametersParams) WithTimeout(timeout time.Duration) *ReportsGetReportParametersParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the reports get report parameters params
func (o *ReportsGetReportParametersParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the reports get report parameters params
func (o *ReportsGetReportParametersParams) WithContext(ctx context.Context) *ReportsGetReportParametersParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the reports get report parameters params
func (o *ReportsGetReportParametersParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the reports get report parameters params
func (o *ReportsGetReportParametersParams) WithHTTPClient(client *http.Client) *ReportsGetReportParametersParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the reports get report parameters params
func (o *ReportsGetReportParametersParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithReportID adds the reportID to the reports get report parameters params
func (o *ReportsGetReportParametersParams) WithReportID(reportID *string) *ReportsGetReportParametersParams {
	o.SetReportID(reportID)
	return o
}

// SetReportID adds the reportId to the reports get report parameters params
func (o *ReportsGetReportParametersParams) SetReportID(reportID *string) {
	o.ReportID = reportID
}

// WriteToRequest writes these params to a swagger request
func (o *ReportsGetReportParametersParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ReportID != nil {

		// query param reportId
		var qrReportID string

		if o.ReportID != nil {
			qrReportID = *o.ReportID
		}
		qReportID := qrReportID
		if qReportID != "" {

			if err := r.SetQueryParam("reportId", qReportID); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}