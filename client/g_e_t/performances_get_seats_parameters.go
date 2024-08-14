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

// NewPerformancesGetSeatsParams creates a new PerformancesGetSeatsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPerformancesGetSeatsParams() *PerformancesGetSeatsParams {
	return &PerformancesGetSeatsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPerformancesGetSeatsParamsWithTimeout creates a new PerformancesGetSeatsParams object
// with the ability to set a timeout on a request.
func NewPerformancesGetSeatsParamsWithTimeout(timeout time.Duration) *PerformancesGetSeatsParams {
	return &PerformancesGetSeatsParams{
		timeout: timeout,
	}
}

// NewPerformancesGetSeatsParamsWithContext creates a new PerformancesGetSeatsParams object
// with the ability to set a context for a request.
func NewPerformancesGetSeatsParamsWithContext(ctx context.Context) *PerformancesGetSeatsParams {
	return &PerformancesGetSeatsParams{
		Context: ctx,
	}
}

// NewPerformancesGetSeatsParamsWithHTTPClient creates a new PerformancesGetSeatsParams object
// with the ability to set a custom HTTPClient for a request.
func NewPerformancesGetSeatsParamsWithHTTPClient(client *http.Client) *PerformancesGetSeatsParams {
	return &PerformancesGetSeatsParams{
		HTTPClient: client,
	}
}

/*
PerformancesGetSeatsParams contains all the parameters to send to the API endpoint

	for the performances get seats operation.

	Typically these are written to a http.Request.
*/
type PerformancesGetSeatsParams struct {

	/* CheckPriceTypeIds.

	   checkPriceTypeIds must be either a list of valid price types or the token "All"
	*/
	CheckPriceTypeIds *string

	/* ConstituentID.

	   Required parameter. Must be a valid constituent ID
	*/
	ConstituentID *string

	/* ModeOfSaleID.

	   Required parameter. Must be a valid MOS id
	*/
	ModeOfSaleID *string

	/* PerformanceID.

	   ID of the performance
	*/
	PerformanceID string

	/* ReturnNonSeats.

	   returnNonSeats indicates if locations on the seat map that are not seats should be included
	*/
	ReturnNonSeats *string

	/* ScreenIds.

	   screenIds must be a comma separated list of valid screen ids for the specified performance
	*/
	ScreenIds *string

	/* SectionIds.

	   sectionIds must be a comma separated list of valid section ids
	*/
	SectionIds *string

	/* ZoneIds.

	   zoneIds must be a comma separated list of valid zone ids
	*/
	ZoneIds *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the performances get seats params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PerformancesGetSeatsParams) WithDefaults() *PerformancesGetSeatsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the performances get seats params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PerformancesGetSeatsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the performances get seats params
func (o *PerformancesGetSeatsParams) WithTimeout(timeout time.Duration) *PerformancesGetSeatsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the performances get seats params
func (o *PerformancesGetSeatsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the performances get seats params
func (o *PerformancesGetSeatsParams) WithContext(ctx context.Context) *PerformancesGetSeatsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the performances get seats params
func (o *PerformancesGetSeatsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the performances get seats params
func (o *PerformancesGetSeatsParams) WithHTTPClient(client *http.Client) *PerformancesGetSeatsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the performances get seats params
func (o *PerformancesGetSeatsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCheckPriceTypeIds adds the checkPriceTypeIds to the performances get seats params
func (o *PerformancesGetSeatsParams) WithCheckPriceTypeIds(checkPriceTypeIds *string) *PerformancesGetSeatsParams {
	o.SetCheckPriceTypeIds(checkPriceTypeIds)
	return o
}

// SetCheckPriceTypeIds adds the checkPriceTypeIds to the performances get seats params
func (o *PerformancesGetSeatsParams) SetCheckPriceTypeIds(checkPriceTypeIds *string) {
	o.CheckPriceTypeIds = checkPriceTypeIds
}

// WithConstituentID adds the constituentID to the performances get seats params
func (o *PerformancesGetSeatsParams) WithConstituentID(constituentID *string) *PerformancesGetSeatsParams {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the performances get seats params
func (o *PerformancesGetSeatsParams) SetConstituentID(constituentID *string) {
	o.ConstituentID = constituentID
}

// WithModeOfSaleID adds the modeOfSaleID to the performances get seats params
func (o *PerformancesGetSeatsParams) WithModeOfSaleID(modeOfSaleID *string) *PerformancesGetSeatsParams {
	o.SetModeOfSaleID(modeOfSaleID)
	return o
}

// SetModeOfSaleID adds the modeOfSaleId to the performances get seats params
func (o *PerformancesGetSeatsParams) SetModeOfSaleID(modeOfSaleID *string) {
	o.ModeOfSaleID = modeOfSaleID
}

// WithPerformanceID adds the performanceID to the performances get seats params
func (o *PerformancesGetSeatsParams) WithPerformanceID(performanceID string) *PerformancesGetSeatsParams {
	o.SetPerformanceID(performanceID)
	return o
}

// SetPerformanceID adds the performanceId to the performances get seats params
func (o *PerformancesGetSeatsParams) SetPerformanceID(performanceID string) {
	o.PerformanceID = performanceID
}

// WithReturnNonSeats adds the returnNonSeats to the performances get seats params
func (o *PerformancesGetSeatsParams) WithReturnNonSeats(returnNonSeats *string) *PerformancesGetSeatsParams {
	o.SetReturnNonSeats(returnNonSeats)
	return o
}

// SetReturnNonSeats adds the returnNonSeats to the performances get seats params
func (o *PerformancesGetSeatsParams) SetReturnNonSeats(returnNonSeats *string) {
	o.ReturnNonSeats = returnNonSeats
}

// WithScreenIds adds the screenIds to the performances get seats params
func (o *PerformancesGetSeatsParams) WithScreenIds(screenIds *string) *PerformancesGetSeatsParams {
	o.SetScreenIds(screenIds)
	return o
}

// SetScreenIds adds the screenIds to the performances get seats params
func (o *PerformancesGetSeatsParams) SetScreenIds(screenIds *string) {
	o.ScreenIds = screenIds
}

// WithSectionIds adds the sectionIds to the performances get seats params
func (o *PerformancesGetSeatsParams) WithSectionIds(sectionIds *string) *PerformancesGetSeatsParams {
	o.SetSectionIds(sectionIds)
	return o
}

// SetSectionIds adds the sectionIds to the performances get seats params
func (o *PerformancesGetSeatsParams) SetSectionIds(sectionIds *string) {
	o.SectionIds = sectionIds
}

// WithZoneIds adds the zoneIds to the performances get seats params
func (o *PerformancesGetSeatsParams) WithZoneIds(zoneIds *string) *PerformancesGetSeatsParams {
	o.SetZoneIds(zoneIds)
	return o
}

// SetZoneIds adds the zoneIds to the performances get seats params
func (o *PerformancesGetSeatsParams) SetZoneIds(zoneIds *string) {
	o.ZoneIds = zoneIds
}

// WriteToRequest writes these params to a swagger request
func (o *PerformancesGetSeatsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.CheckPriceTypeIds != nil {

		// query param checkPriceTypeIds
		var qrCheckPriceTypeIds string

		if o.CheckPriceTypeIds != nil {
			qrCheckPriceTypeIds = *o.CheckPriceTypeIds
		}
		qCheckPriceTypeIds := qrCheckPriceTypeIds
		if qCheckPriceTypeIds != "" {

			if err := r.SetQueryParam("checkPriceTypeIds", qCheckPriceTypeIds); err != nil {
				return err
			}
		}
	}

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

	if o.ModeOfSaleID != nil {

		// query param modeOfSaleId
		var qrModeOfSaleID string

		if o.ModeOfSaleID != nil {
			qrModeOfSaleID = *o.ModeOfSaleID
		}
		qModeOfSaleID := qrModeOfSaleID
		if qModeOfSaleID != "" {

			if err := r.SetQueryParam("modeOfSaleId", qModeOfSaleID); err != nil {
				return err
			}
		}
	}

	// path param performanceId
	if err := r.SetPathParam("performanceId", o.PerformanceID); err != nil {
		return err
	}

	if o.ReturnNonSeats != nil {

		// query param returnNonSeats
		var qrReturnNonSeats string

		if o.ReturnNonSeats != nil {
			qrReturnNonSeats = *o.ReturnNonSeats
		}
		qReturnNonSeats := qrReturnNonSeats
		if qReturnNonSeats != "" {

			if err := r.SetQueryParam("returnNonSeats", qReturnNonSeats); err != nil {
				return err
			}
		}
	}

	if o.ScreenIds != nil {

		// query param screenIds
		var qrScreenIds string

		if o.ScreenIds != nil {
			qrScreenIds = *o.ScreenIds
		}
		qScreenIds := qrScreenIds
		if qScreenIds != "" {

			if err := r.SetQueryParam("screenIds", qScreenIds); err != nil {
				return err
			}
		}
	}

	if o.SectionIds != nil {

		// query param sectionIds
		var qrSectionIds string

		if o.SectionIds != nil {
			qrSectionIds = *o.SectionIds
		}
		qSectionIds := qrSectionIds
		if qSectionIds != "" {

			if err := r.SetQueryParam("sectionIds", qSectionIds); err != nil {
				return err
			}
		}
	}

	if o.ZoneIds != nil {

		// query param zoneIds
		var qrZoneIds string

		if o.ZoneIds != nil {
			qrZoneIds = *o.ZoneIds
		}
		qZoneIds := qrZoneIds
		if qZoneIds != "" {

			if err := r.SetQueryParam("zoneIds", qZoneIds); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}