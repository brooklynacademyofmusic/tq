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

// NewPlanStatusesGetSummariesParams creates a new PlanStatusesGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPlanStatusesGetSummariesParams() *PlanStatusesGetSummariesParams {
	return &PlanStatusesGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPlanStatusesGetSummariesParamsWithTimeout creates a new PlanStatusesGetSummariesParams object
// with the ability to set a timeout on a request.
func NewPlanStatusesGetSummariesParamsWithTimeout(timeout time.Duration) *PlanStatusesGetSummariesParams {
	return &PlanStatusesGetSummariesParams{
		timeout: timeout,
	}
}

// NewPlanStatusesGetSummariesParamsWithContext creates a new PlanStatusesGetSummariesParams object
// with the ability to set a context for a request.
func NewPlanStatusesGetSummariesParamsWithContext(ctx context.Context) *PlanStatusesGetSummariesParams {
	return &PlanStatusesGetSummariesParams{
		Context: ctx,
	}
}

// NewPlanStatusesGetSummariesParamsWithHTTPClient creates a new PlanStatusesGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewPlanStatusesGetSummariesParamsWithHTTPClient(client *http.Client) *PlanStatusesGetSummariesParams {
	return &PlanStatusesGetSummariesParams{
		HTTPClient: client,
	}
}

/*
PlanStatusesGetSummariesParams contains all the parameters to send to the API endpoint

	for the plan statuses get summaries operation.

	Typically these are written to a http.Request.
*/
type PlanStatusesGetSummariesParams struct {
	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the plan statuses get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PlanStatusesGetSummariesParams) WithDefaults() *PlanStatusesGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the plan statuses get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PlanStatusesGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the plan statuses get summaries params
func (o *PlanStatusesGetSummariesParams) WithTimeout(timeout time.Duration) *PlanStatusesGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the plan statuses get summaries params
func (o *PlanStatusesGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the plan statuses get summaries params
func (o *PlanStatusesGetSummariesParams) WithContext(ctx context.Context) *PlanStatusesGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the plan statuses get summaries params
func (o *PlanStatusesGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the plan statuses get summaries params
func (o *PlanStatusesGetSummariesParams) WithHTTPClient(client *http.Client) *PlanStatusesGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the plan statuses get summaries params
func (o *PlanStatusesGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WriteToRequest writes these params to a swagger request
func (o *PlanStatusesGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}