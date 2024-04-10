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

// NewListsResultsParams creates a new ListsResultsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewListsResultsParams() *ListsResultsParams {
	return &ListsResultsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewListsResultsParamsWithTimeout creates a new ListsResultsParams object
// with the ability to set a timeout on a request.
func NewListsResultsParamsWithTimeout(timeout time.Duration) *ListsResultsParams {
	return &ListsResultsParams{
		timeout: timeout,
	}
}

// NewListsResultsParamsWithContext creates a new ListsResultsParams object
// with the ability to set a context for a request.
func NewListsResultsParamsWithContext(ctx context.Context) *ListsResultsParams {
	return &ListsResultsParams{
		Context: ctx,
	}
}

// NewListsResultsParamsWithHTTPClient creates a new ListsResultsParams object
// with the ability to set a custom HTTPClient for a request.
func NewListsResultsParamsWithHTTPClient(client *http.Client) *ListsResultsParams {
	return &ListsResultsParams{
		HTTPClient: client,
	}
}

/*
ListsResultsParams contains all the parameters to send to the API endpoint

	for the lists results operation.

	Typically these are written to a http.Request.
*/
type ListsResultsParams struct {

	// ListID.
	ListID string

	// OutputResultRequest.
	OutputResultRequest *models.OutputResultRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the lists results params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListsResultsParams) WithDefaults() *ListsResultsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the lists results params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ListsResultsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the lists results params
func (o *ListsResultsParams) WithTimeout(timeout time.Duration) *ListsResultsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the lists results params
func (o *ListsResultsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the lists results params
func (o *ListsResultsParams) WithContext(ctx context.Context) *ListsResultsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the lists results params
func (o *ListsResultsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the lists results params
func (o *ListsResultsParams) WithHTTPClient(client *http.Client) *ListsResultsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the lists results params
func (o *ListsResultsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithListID adds the listID to the lists results params
func (o *ListsResultsParams) WithListID(listID string) *ListsResultsParams {
	o.SetListID(listID)
	return o
}

// SetListID adds the listId to the lists results params
func (o *ListsResultsParams) SetListID(listID string) {
	o.ListID = listID
}

// WithOutputResultRequest adds the outputResultRequest to the lists results params
func (o *ListsResultsParams) WithOutputResultRequest(outputResultRequest *models.OutputResultRequest) *ListsResultsParams {
	o.SetOutputResultRequest(outputResultRequest)
	return o
}

// SetOutputResultRequest adds the outputResultRequest to the lists results params
func (o *ListsResultsParams) SetOutputResultRequest(outputResultRequest *models.OutputResultRequest) {
	o.OutputResultRequest = outputResultRequest
}

// WriteToRequest writes these params to a swagger request
func (o *ListsResultsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param listId
	if err := r.SetPathParam("listId", o.ListID); err != nil {
		return err
	}
	if o.OutputResultRequest != nil {
		if err := r.SetBodyParam(o.OutputResultRequest); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}