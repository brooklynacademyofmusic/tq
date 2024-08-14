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

// NewAssetsGetAllParams creates a new AssetsGetAllParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewAssetsGetAllParams() *AssetsGetAllParams {
	return &AssetsGetAllParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewAssetsGetAllParamsWithTimeout creates a new AssetsGetAllParams object
// with the ability to set a timeout on a request.
func NewAssetsGetAllParamsWithTimeout(timeout time.Duration) *AssetsGetAllParams {
	return &AssetsGetAllParams{
		timeout: timeout,
	}
}

// NewAssetsGetAllParamsWithContext creates a new AssetsGetAllParams object
// with the ability to set a context for a request.
func NewAssetsGetAllParamsWithContext(ctx context.Context) *AssetsGetAllParams {
	return &AssetsGetAllParams{
		Context: ctx,
	}
}

// NewAssetsGetAllParamsWithHTTPClient creates a new AssetsGetAllParams object
// with the ability to set a custom HTTPClient for a request.
func NewAssetsGetAllParamsWithHTTPClient(client *http.Client) *AssetsGetAllParams {
	return &AssetsGetAllParams{
		HTTPClient: client,
	}
}

/*
AssetsGetAllParams contains all the parameters to send to the API endpoint

	for the assets get all operation.

	Typically these are written to a http.Request.
*/
type AssetsGetAllParams struct {

	/* ConstituentID.

	   Limit results by constituent
	*/
	ConstituentID *string

	/* IncludeAffiliations.

	   Include all of the constituent's affiliates in the results (default: true)
	*/
	IncludeAffiliations *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the assets get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AssetsGetAllParams) WithDefaults() *AssetsGetAllParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the assets get all params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *AssetsGetAllParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the assets get all params
func (o *AssetsGetAllParams) WithTimeout(timeout time.Duration) *AssetsGetAllParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the assets get all params
func (o *AssetsGetAllParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the assets get all params
func (o *AssetsGetAllParams) WithContext(ctx context.Context) *AssetsGetAllParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the assets get all params
func (o *AssetsGetAllParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the assets get all params
func (o *AssetsGetAllParams) WithHTTPClient(client *http.Client) *AssetsGetAllParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the assets get all params
func (o *AssetsGetAllParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConstituentID adds the constituentID to the assets get all params
func (o *AssetsGetAllParams) WithConstituentID(constituentID *string) *AssetsGetAllParams {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the assets get all params
func (o *AssetsGetAllParams) SetConstituentID(constituentID *string) {
	o.ConstituentID = constituentID
}

// WithIncludeAffiliations adds the includeAffiliations to the assets get all params
func (o *AssetsGetAllParams) WithIncludeAffiliations(includeAffiliations *string) *AssetsGetAllParams {
	o.SetIncludeAffiliations(includeAffiliations)
	return o
}

// SetIncludeAffiliations adds the includeAffiliations to the assets get all params
func (o *AssetsGetAllParams) SetIncludeAffiliations(includeAffiliations *string) {
	o.IncludeAffiliations = includeAffiliations
}

// WriteToRequest writes these params to a swagger request
func (o *AssetsGetAllParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.ConstituentID != nil {

		// query param constituentId
		var qrConstituentID string

		if o.ConstituentID != nil {
			qrConstituentID = *o.ConstituentID
		}
		qConstituentID := qrConstituentID
		if qConstituentID != "" {

			if err := r.SetQueryParam("constituentId", qConstituentID); err != nil {
				return err
			}
		}
	}

	if o.IncludeAffiliations != nil {

		// query param includeAffiliations
		var qrIncludeAffiliations string

		if o.IncludeAffiliations != nil {
			qrIncludeAffiliations = *o.IncludeAffiliations
		}
		qIncludeAffiliations := qrIncludeAffiliations
		if qIncludeAffiliations != "" {

			if err := r.SetQueryParam("includeAffiliations", qIncludeAffiliations); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}