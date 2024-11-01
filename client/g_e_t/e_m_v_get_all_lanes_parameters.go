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

// NewEMVGetAllLanesParams creates a new EMVGetAllLanesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewEMVGetAllLanesParams() *EMVGetAllLanesParams {
	return &EMVGetAllLanesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewEMVGetAllLanesParamsWithTimeout creates a new EMVGetAllLanesParams object
// with the ability to set a timeout on a request.
func NewEMVGetAllLanesParamsWithTimeout(timeout time.Duration) *EMVGetAllLanesParams {
	return &EMVGetAllLanesParams{
		timeout: timeout,
	}
}

// NewEMVGetAllLanesParamsWithContext creates a new EMVGetAllLanesParams object
// with the ability to set a context for a request.
func NewEMVGetAllLanesParamsWithContext(ctx context.Context) *EMVGetAllLanesParams {
	return &EMVGetAllLanesParams{
		Context: ctx,
	}
}

// NewEMVGetAllLanesParamsWithHTTPClient creates a new EMVGetAllLanesParams object
// with the ability to set a custom HTTPClient for a request.
func NewEMVGetAllLanesParamsWithHTTPClient(client *http.Client) *EMVGetAllLanesParams {
	return &EMVGetAllLanesParams{
		HTTPClient: client,
	}
}

/*
EMVGetAllLanesParams contains all the parameters to send to the API endpoint

	for the e m v get all lanes operation.

	Typically these are written to a http.Request.
*/
type EMVGetAllLanesParams struct {

	// Cert.
	Cert *string

	// Merchant.
	Merchant *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the e m v get all lanes params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EMVGetAllLanesParams) WithDefaults() *EMVGetAllLanesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the e m v get all lanes params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EMVGetAllLanesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the e m v get all lanes params
func (o *EMVGetAllLanesParams) WithTimeout(timeout time.Duration) *EMVGetAllLanesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the e m v get all lanes params
func (o *EMVGetAllLanesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the e m v get all lanes params
func (o *EMVGetAllLanesParams) WithContext(ctx context.Context) *EMVGetAllLanesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the e m v get all lanes params
func (o *EMVGetAllLanesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the e m v get all lanes params
func (o *EMVGetAllLanesParams) WithHTTPClient(client *http.Client) *EMVGetAllLanesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the e m v get all lanes params
func (o *EMVGetAllLanesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCert adds the cert to the e m v get all lanes params
func (o *EMVGetAllLanesParams) WithCert(cert *string) *EMVGetAllLanesParams {
	o.SetCert(cert)
	return o
}

// SetCert adds the cert to the e m v get all lanes params
func (o *EMVGetAllLanesParams) SetCert(cert *string) {
	o.Cert = cert
}

// WithMerchant adds the merchant to the e m v get all lanes params
func (o *EMVGetAllLanesParams) WithMerchant(merchant *string) *EMVGetAllLanesParams {
	o.SetMerchant(merchant)
	return o
}

// SetMerchant adds the merchant to the e m v get all lanes params
func (o *EMVGetAllLanesParams) SetMerchant(merchant *string) {
	o.Merchant = merchant
}

// WriteToRequest writes these params to a swagger request
func (o *EMVGetAllLanesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Cert != nil {

		// query param cert
		var qrCert string

		if o.Cert != nil {
			qrCert = *o.Cert
		}
		qCert := qrCert
		if qCert != "" {

			if err := r.SetQueryParam("cert", qCert); err != nil {
				return err
			}
		}
	}

	if o.Merchant != nil {

		// query param merchant
		var qrMerchant string

		if o.Merchant != nil {
			qrMerchant = *o.Merchant
		}
		qMerchant := qrMerchant
		if qMerchant != "" {

			if err := r.SetQueryParam("merchant", qMerchant); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}