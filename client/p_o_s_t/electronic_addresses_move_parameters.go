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
)

// NewElectronicAddressesMoveParams creates a new ElectronicAddressesMoveParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewElectronicAddressesMoveParams() *ElectronicAddressesMoveParams {
	return &ElectronicAddressesMoveParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewElectronicAddressesMoveParamsWithTimeout creates a new ElectronicAddressesMoveParams object
// with the ability to set a timeout on a request.
func NewElectronicAddressesMoveParamsWithTimeout(timeout time.Duration) *ElectronicAddressesMoveParams {
	return &ElectronicAddressesMoveParams{
		timeout: timeout,
	}
}

// NewElectronicAddressesMoveParamsWithContext creates a new ElectronicAddressesMoveParams object
// with the ability to set a context for a request.
func NewElectronicAddressesMoveParamsWithContext(ctx context.Context) *ElectronicAddressesMoveParams {
	return &ElectronicAddressesMoveParams{
		Context: ctx,
	}
}

// NewElectronicAddressesMoveParamsWithHTTPClient creates a new ElectronicAddressesMoveParams object
// with the ability to set a custom HTTPClient for a request.
func NewElectronicAddressesMoveParamsWithHTTPClient(client *http.Client) *ElectronicAddressesMoveParams {
	return &ElectronicAddressesMoveParams{
		HTTPClient: client,
	}
}

/*
ElectronicAddressesMoveParams contains all the parameters to send to the API endpoint

	for the electronic addresses move operation.

	Typically these are written to a http.Request.
*/
type ElectronicAddressesMoveParams struct {

	// ConstituentID.
	ConstituentID string

	// ElectronicAddressID.
	ElectronicAddressID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the electronic addresses move params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ElectronicAddressesMoveParams) WithDefaults() *ElectronicAddressesMoveParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the electronic addresses move params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ElectronicAddressesMoveParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) WithTimeout(timeout time.Duration) *ElectronicAddressesMoveParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) WithContext(ctx context.Context) *ElectronicAddressesMoveParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) WithHTTPClient(client *http.Client) *ElectronicAddressesMoveParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithConstituentID adds the constituentID to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) WithConstituentID(constituentID string) *ElectronicAddressesMoveParams {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) SetConstituentID(constituentID string) {
	o.ConstituentID = constituentID
}

// WithElectronicAddressID adds the electronicAddressID to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) WithElectronicAddressID(electronicAddressID string) *ElectronicAddressesMoveParams {
	o.SetElectronicAddressID(electronicAddressID)
	return o
}

// SetElectronicAddressID adds the electronicAddressId to the electronic addresses move params
func (o *ElectronicAddressesMoveParams) SetElectronicAddressID(electronicAddressID string) {
	o.ElectronicAddressID = electronicAddressID
}

// WriteToRequest writes these params to a swagger request
func (o *ElectronicAddressesMoveParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param constituentId
	if err := r.SetPathParam("constituentId", o.ConstituentID); err != nil {
		return err
	}

	// path param electronicAddressId
	if err := r.SetPathParam("electronicAddressId", o.ElectronicAddressID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}