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

// NewPackagesGetSeatSummariesParams creates a new PackagesGetSeatSummariesParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPackagesGetSeatSummariesParams() *PackagesGetSeatSummariesParams {
	return &PackagesGetSeatSummariesParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPackagesGetSeatSummariesParamsWithTimeout creates a new PackagesGetSeatSummariesParams object
// with the ability to set a timeout on a request.
func NewPackagesGetSeatSummariesParamsWithTimeout(timeout time.Duration) *PackagesGetSeatSummariesParams {
	return &PackagesGetSeatSummariesParams{
		timeout: timeout,
	}
}

// NewPackagesGetSeatSummariesParamsWithContext creates a new PackagesGetSeatSummariesParams object
// with the ability to set a context for a request.
func NewPackagesGetSeatSummariesParamsWithContext(ctx context.Context) *PackagesGetSeatSummariesParams {
	return &PackagesGetSeatSummariesParams{
		Context: ctx,
	}
}

// NewPackagesGetSeatSummariesParamsWithHTTPClient creates a new PackagesGetSeatSummariesParams object
// with the ability to set a custom HTTPClient for a request.
func NewPackagesGetSeatSummariesParamsWithHTTPClient(client *http.Client) *PackagesGetSeatSummariesParams {
	return &PackagesGetSeatSummariesParams{
		HTTPClient: client,
	}
}

/*
PackagesGetSeatSummariesParams contains all the parameters to send to the API endpoint

	for the packages get seat summaries operation.

	Typically these are written to a http.Request.
*/
type PackagesGetSeatSummariesParams struct {

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

	/* PackageID.

	   ID of the fixed seat package
	*/
	PackageID string

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

// WithDefaults hydrates default values in the packages get seat summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PackagesGetSeatSummariesParams) WithDefaults() *PackagesGetSeatSummariesParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the packages get seat summaries params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PackagesGetSeatSummariesParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithTimeout(timeout time.Duration) *PackagesGetSeatSummariesParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithContext(ctx context.Context) *PackagesGetSeatSummariesParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithHTTPClient(client *http.Client) *PackagesGetSeatSummariesParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCheckPriceTypeIds adds the checkPriceTypeIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithCheckPriceTypeIds(checkPriceTypeIds *string) *PackagesGetSeatSummariesParams {
	o.SetCheckPriceTypeIds(checkPriceTypeIds)
	return o
}

// SetCheckPriceTypeIds adds the checkPriceTypeIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetCheckPriceTypeIds(checkPriceTypeIds *string) {
	o.CheckPriceTypeIds = checkPriceTypeIds
}

// WithConstituentID adds the constituentID to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithConstituentID(constituentID *string) *PackagesGetSeatSummariesParams {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetConstituentID(constituentID *string) {
	o.ConstituentID = constituentID
}

// WithModeOfSaleID adds the modeOfSaleID to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithModeOfSaleID(modeOfSaleID *string) *PackagesGetSeatSummariesParams {
	o.SetModeOfSaleID(modeOfSaleID)
	return o
}

// SetModeOfSaleID adds the modeOfSaleId to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetModeOfSaleID(modeOfSaleID *string) {
	o.ModeOfSaleID = modeOfSaleID
}

// WithPackageID adds the packageID to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithPackageID(packageID string) *PackagesGetSeatSummariesParams {
	o.SetPackageID(packageID)
	return o
}

// SetPackageID adds the packageId to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetPackageID(packageID string) {
	o.PackageID = packageID
}

// WithScreenIds adds the screenIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithScreenIds(screenIds *string) *PackagesGetSeatSummariesParams {
	o.SetScreenIds(screenIds)
	return o
}

// SetScreenIds adds the screenIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetScreenIds(screenIds *string) {
	o.ScreenIds = screenIds
}

// WithSectionIds adds the sectionIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithSectionIds(sectionIds *string) *PackagesGetSeatSummariesParams {
	o.SetSectionIds(sectionIds)
	return o
}

// SetSectionIds adds the sectionIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetSectionIds(sectionIds *string) {
	o.SectionIds = sectionIds
}

// WithZoneIds adds the zoneIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) WithZoneIds(zoneIds *string) *PackagesGetSeatSummariesParams {
	o.SetZoneIds(zoneIds)
	return o
}

// SetZoneIds adds the zoneIds to the packages get seat summaries params
func (o *PackagesGetSeatSummariesParams) SetZoneIds(zoneIds *string) {
	o.ZoneIds = zoneIds
}

// WriteToRequest writes these params to a swagger request
func (o *PackagesGetSeatSummariesParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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

	// path param packageId
	if err := r.SetPathParam("packageId", o.PackageID); err != nil {
		return err
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