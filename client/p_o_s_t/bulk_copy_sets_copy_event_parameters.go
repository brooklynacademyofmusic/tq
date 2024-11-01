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

// NewBulkCopySetsCopyEventParams creates a new BulkCopySetsCopyEventParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBulkCopySetsCopyEventParams() *BulkCopySetsCopyEventParams {
	return &BulkCopySetsCopyEventParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBulkCopySetsCopyEventParamsWithTimeout creates a new BulkCopySetsCopyEventParams object
// with the ability to set a timeout on a request.
func NewBulkCopySetsCopyEventParamsWithTimeout(timeout time.Duration) *BulkCopySetsCopyEventParams {
	return &BulkCopySetsCopyEventParams{
		timeout: timeout,
	}
}

// NewBulkCopySetsCopyEventParamsWithContext creates a new BulkCopySetsCopyEventParams object
// with the ability to set a context for a request.
func NewBulkCopySetsCopyEventParamsWithContext(ctx context.Context) *BulkCopySetsCopyEventParams {
	return &BulkCopySetsCopyEventParams{
		Context: ctx,
	}
}

// NewBulkCopySetsCopyEventParamsWithHTTPClient creates a new BulkCopySetsCopyEventParams object
// with the ability to set a custom HTTPClient for a request.
func NewBulkCopySetsCopyEventParamsWithHTTPClient(client *http.Client) *BulkCopySetsCopyEventParams {
	return &BulkCopySetsCopyEventParams{
		HTTPClient: client,
	}
}

/*
BulkCopySetsCopyEventParams contains all the parameters to send to the API endpoint

	for the bulk copy sets copy event operation.

	Typically these are written to a http.Request.
*/
type BulkCopySetsCopyEventParams struct {

	// BulkCopyEventRequest.
	BulkCopyEventRequest *models.BulkCopyEventRequest

	// BulkCopySetID.
	BulkCopySetID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the bulk copy sets copy event params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkCopySetsCopyEventParams) WithDefaults() *BulkCopySetsCopyEventParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the bulk copy sets copy event params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BulkCopySetsCopyEventParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) WithTimeout(timeout time.Duration) *BulkCopySetsCopyEventParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) WithContext(ctx context.Context) *BulkCopySetsCopyEventParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) WithHTTPClient(client *http.Client) *BulkCopySetsCopyEventParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBulkCopyEventRequest adds the bulkCopyEventRequest to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) WithBulkCopyEventRequest(bulkCopyEventRequest *models.BulkCopyEventRequest) *BulkCopySetsCopyEventParams {
	o.SetBulkCopyEventRequest(bulkCopyEventRequest)
	return o
}

// SetBulkCopyEventRequest adds the bulkCopyEventRequest to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) SetBulkCopyEventRequest(bulkCopyEventRequest *models.BulkCopyEventRequest) {
	o.BulkCopyEventRequest = bulkCopyEventRequest
}

// WithBulkCopySetID adds the bulkCopySetID to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) WithBulkCopySetID(bulkCopySetID string) *BulkCopySetsCopyEventParams {
	o.SetBulkCopySetID(bulkCopySetID)
	return o
}

// SetBulkCopySetID adds the bulkCopySetId to the bulk copy sets copy event params
func (o *BulkCopySetsCopyEventParams) SetBulkCopySetID(bulkCopySetID string) {
	o.BulkCopySetID = bulkCopySetID
}

// WriteToRequest writes these params to a swagger request
func (o *BulkCopySetsCopyEventParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.BulkCopyEventRequest != nil {
		if err := r.SetBodyParam(o.BulkCopyEventRequest); err != nil {
			return err
		}
	}

	// path param bulkCopySetId
	if err := r.SetPathParam("bulkCopySetId", o.BulkCopySetID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}