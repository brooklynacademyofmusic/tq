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

// NewMembershipLevelsGetSummariesParams creates a new MembershipLevelsGetSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewMembershipLevelsGetSummariesParams() *MembershipLevelsGetSummariesParams {
	return &MembershipLevelsGetSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewMembershipLevelsGetSummariesParamsWithTimeout creates a new MembershipLevelsGetSummariesParams object
// with the ability to set a timeout on a request.
func NewMembershipLevelsGetSummariesParamsWithTimeout(timeout time.Duration) *MembershipLevelsGetSummariesParams {
	return &MembershipLevelsGetSummariesParams{
		timeout: timeout,
	}
}

// NewMembershipLevelsGetSummariesParamsWithContext creates a new MembershipLevelsGetSummariesParams object
// with the ability to set a context for a request.
func NewMembershipLevelsGetSummariesParamsWithContext(ctx context.Context) *MembershipLevelsGetSummariesParams {
	return &MembershipLevelsGetSummariesParams{
		Context: ctx,
	}
}

// NewMembershipLevelsGetSummariesParamsWithHTTPClient creates a new MembershipLevelsGetSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewMembershipLevelsGetSummariesParamsWithHTTPClient(client *http.Client) *MembershipLevelsGetSummariesParams {
	return &MembershipLevelsGetSummariesParams{
		HTTPClient: client,
	}
}

/*
MembershipLevelsGetSummariesParams contains all the parameters to send to the API endpoint

	for the membership levels get summaries operation.

	Typically these are written to a http.Request.
*/
type MembershipLevelsGetSummariesParams struct {

	// MembershipOrgID.
	MembershipOrgID *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the membership levels get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *MembershipLevelsGetSummariesParams) WithDefaults() *MembershipLevelsGetSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the membership levels get summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *MembershipLevelsGetSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) WithTimeout(timeout time.Duration) *MembershipLevelsGetSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) WithContext(ctx context.Context) *MembershipLevelsGetSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) WithHTTPClient(client *http.Client) *MembershipLevelsGetSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithMembershipOrgID adds the membershipOrgID to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) WithMembershipOrgID(membershipOrgID *string) *MembershipLevelsGetSummariesParams {
	o.SetMembershipOrgID(membershipOrgID)
	return o
}

// SetMembershipOrgID adds the membershipOrgId to the membership levels get summaries params
func (o *MembershipLevelsGetSummariesParams) SetMembershipOrgID(membershipOrgID *string) {
	o.MembershipOrgID = membershipOrgID
}

// WriteToRequest writes these params to a swagger request
func (o *MembershipLevelsGetSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.MembershipOrgID != nil {

		// query param membershipOrgId
		var qrMembershipOrgID string

		if o.MembershipOrgID != nil {
			qrMembershipOrgID = *o.MembershipOrgID
		}
		qMembershipOrgID := qrMembershipOrgID
		if qMembershipOrgID != "" {

			if err := r.SetQueryParam("membershipOrgId", qMembershipOrgID); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}