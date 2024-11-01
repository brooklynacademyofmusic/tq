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

// NewBookingsGetAllDocumentsParams creates a new BookingsGetAllDocumentsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewBookingsGetAllDocumentsParams() *BookingsGetAllDocumentsParams {
	return &BookingsGetAllDocumentsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewBookingsGetAllDocumentsParamsWithTimeout creates a new BookingsGetAllDocumentsParams object
// with the ability to set a timeout on a request.
func NewBookingsGetAllDocumentsParamsWithTimeout(timeout time.Duration) *BookingsGetAllDocumentsParams {
	return &BookingsGetAllDocumentsParams{
		timeout: timeout,
	}
}

// NewBookingsGetAllDocumentsParamsWithContext creates a new BookingsGetAllDocumentsParams object
// with the ability to set a context for a request.
func NewBookingsGetAllDocumentsParamsWithContext(ctx context.Context) *BookingsGetAllDocumentsParams {
	return &BookingsGetAllDocumentsParams{
		Context: ctx,
	}
}

// NewBookingsGetAllDocumentsParamsWithHTTPClient creates a new BookingsGetAllDocumentsParams object
// with the ability to set a custom HTTPClient for a request.
func NewBookingsGetAllDocumentsParamsWithHTTPClient(client *http.Client) *BookingsGetAllDocumentsParams {
	return &BookingsGetAllDocumentsParams{
		HTTPClient: client,
	}
}

/*
BookingsGetAllDocumentsParams contains all the parameters to send to the API endpoint

	for the bookings get all documents operation.

	Typically these are written to a http.Request.
*/
type BookingsGetAllDocumentsParams struct {

	// BookingID.
	BookingID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the bookings get all documents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BookingsGetAllDocumentsParams) WithDefaults() *BookingsGetAllDocumentsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the bookings get all documents params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *BookingsGetAllDocumentsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) WithTimeout(timeout time.Duration) *BookingsGetAllDocumentsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) WithContext(ctx context.Context) *BookingsGetAllDocumentsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) WithHTTPClient(client *http.Client) *BookingsGetAllDocumentsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBookingID adds the bookingID to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) WithBookingID(bookingID string) *BookingsGetAllDocumentsParams {
	o.SetBookingID(bookingID)
	return o
}

// SetBookingID adds the bookingId to the bookings get all documents params
func (o *BookingsGetAllDocumentsParams) SetBookingID(bookingID string) {
	o.BookingID = bookingID
}

// WriteToRequest writes these params to a swagger request
func (o *BookingsGetAllDocumentsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param bookingId
	if err := r.SetPathParam("bookingId", o.BookingID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}