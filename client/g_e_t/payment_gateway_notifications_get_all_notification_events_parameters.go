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

// NewPaymentGatewayNotificationsGetAllNotificationEventsParams creates a new PaymentGatewayNotificationsGetAllNotificationEventsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPaymentGatewayNotificationsGetAllNotificationEventsParams() *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	return &PaymentGatewayNotificationsGetAllNotificationEventsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPaymentGatewayNotificationsGetAllNotificationEventsParamsWithTimeout creates a new PaymentGatewayNotificationsGetAllNotificationEventsParams object
// with the ability to set a timeout on a request.
func NewPaymentGatewayNotificationsGetAllNotificationEventsParamsWithTimeout(timeout time.Duration) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	return &PaymentGatewayNotificationsGetAllNotificationEventsParams{
		timeout: timeout,
	}
}

// NewPaymentGatewayNotificationsGetAllNotificationEventsParamsWithContext creates a new PaymentGatewayNotificationsGetAllNotificationEventsParams object
// with the ability to set a context for a request.
func NewPaymentGatewayNotificationsGetAllNotificationEventsParamsWithContext(ctx context.Context) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	return &PaymentGatewayNotificationsGetAllNotificationEventsParams{
		Context: ctx,
	}
}

// NewPaymentGatewayNotificationsGetAllNotificationEventsParamsWithHTTPClient creates a new PaymentGatewayNotificationsGetAllNotificationEventsParams object
// with the ability to set a custom HTTPClient for a request.
func NewPaymentGatewayNotificationsGetAllNotificationEventsParamsWithHTTPClient(client *http.Client) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	return &PaymentGatewayNotificationsGetAllNotificationEventsParams{
		HTTPClient: client,
	}
}

/*
PaymentGatewayNotificationsGetAllNotificationEventsParams contains all the parameters to send to the API endpoint

	for the payment gateway notifications get all notification events operation.

	Typically these are written to a http.Request.
*/
type PaymentGatewayNotificationsGetAllNotificationEventsParams struct {

	/* NotificationType.

	   Optional filter for the notification type.
	*/
	NotificationType string

	/* Reference.

	   Reference for the notification event. For Tessitura Merchant Services, this is the merchant reference.
	*/
	Reference string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the payment gateway notifications get all notification events params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WithDefaults() *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the payment gateway notifications get all notification events params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WithTimeout(timeout time.Duration) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WithContext(ctx context.Context) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WithHTTPClient(client *http.Client) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithNotificationType adds the notificationType to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WithNotificationType(notificationType string) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	o.SetNotificationType(notificationType)
	return o
}

// SetNotificationType adds the notificationType to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) SetNotificationType(notificationType string) {
	o.NotificationType = notificationType
}

// WithReference adds the reference to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WithReference(reference string) *PaymentGatewayNotificationsGetAllNotificationEventsParams {
	o.SetReference(reference)
	return o
}

// SetReference adds the reference to the payment gateway notifications get all notification events params
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) SetReference(reference string) {
	o.Reference = reference
}

// WriteToRequest writes these params to a swagger request
func (o *PaymentGatewayNotificationsGetAllNotificationEventsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param notificationType
	qrNotificationType := o.NotificationType
	qNotificationType := qrNotificationType
	if qNotificationType != "" {

		if err := r.SetQueryParam("notificationType", qNotificationType); err != nil {
			return err
		}
	}

	// query param reference
	qrReference := o.Reference
	qReference := qrReference
	if qReference != "" {

		if err := r.SetQueryParam("reference", qReference); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}