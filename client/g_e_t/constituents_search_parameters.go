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

// NewConstituentsSearchParams creates a new ConstituentsSearchParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewConstituentsSearchParams() *ConstituentsSearchParams {
	return &ConstituentsSearchParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewConstituentsSearchParamsWithTimeout creates a new ConstituentsSearchParams object
// with the ability to set a timeout on a request.
func NewConstituentsSearchParamsWithTimeout(timeout time.Duration) *ConstituentsSearchParams {
	return &ConstituentsSearchParams{
		timeout: timeout,
	}
}

// NewConstituentsSearchParamsWithContext creates a new ConstituentsSearchParams object
// with the ability to set a context for a request.
func NewConstituentsSearchParamsWithContext(ctx context.Context) *ConstituentsSearchParams {
	return &ConstituentsSearchParams{
		Context: ctx,
	}
}

// NewConstituentsSearchParamsWithHTTPClient creates a new ConstituentsSearchParams object
// with the ability to set a custom HTTPClient for a request.
func NewConstituentsSearchParamsWithHTTPClient(client *http.Client) *ConstituentsSearchParams {
	return &ConstituentsSearchParams{
		HTTPClient: client,
	}
}

/*
ConstituentsSearchParams contains all the parameters to send to the API endpoint

	for the constituents search operation.

	Typically these are written to a http.Request.
*/
type ConstituentsSearchParams struct {

	/* Atype.

	   Advanced type to clarify what type of search when "type" is set to Advanced.  Possible values are Customer Service No, Email, Gift Certificate No, Order No, Phone, Web Login. (Encode spaces in URI)
	*/
	Atype *string

	/* ConstituencyIds.

	   Search results filter to limit results to constituents belonging to passed constituencies. Pass as comma-delimited string (1,3,4, e.g.). Applies to all search modes.
	*/
	ConstituencyIds *string

	/* ConstituentGroups.

	   One of individuals,organizations,households or comma separated combination. Leave blank to include all.
	*/
	ConstituentGroups *string

	/* ConstituentID.

	   Direct constituent id search in Basic search type only.  Can also just use /Search?q=## as a substitute, which does a fluent search directly for a constituent.
	*/
	ConstituentID *string

	/* Dup.

	   Boolean whether to include affiliated constituents in the search results. Used in all search types.
	*/
	Dup *string

	/* Fn.

	   First name search value used in Basic search type only.
	*/
	Fn *string

	/* IncludeAffiliates.

	   Boolean whether to include affiliated constituents in the search results. Used in all search types.
	*/
	IncludeAffiliates *string

	/* Key.

	   Only used in Attribute search type.  Keyword for filter expression, passing description from T_KEYWORD (ReferenceData/Keywords).  Used in combination with op and value params.
	*/
	Key *string

	/* ListID.

	   Search results filter to limit results to constituents contained in the supplied list. Applies to all search modes.
	*/
	ListID *string

	/* Ln.

	   Last name search value used in Basic search type only.
	*/
	Ln *string

	/* Op.

	   Operator for filter expression.  Possible values are Equals, LessThan, GreaterThan, or Like. Used in combination with key and value params.  Only used for Attribute search types.
	*/
	Op *string

	/* Page.

	   If passed results are paginated.  By default no pagination occurs. The param pageSize must be provided if page is provided.
	*/
	Page *string

	/* PageSize.

	   If passed results are paginated.  By default no pagination occurs. The param page must be provided if pageSize is provided.
	*/
	PageSize *string

	/* Post.

	   Postal code filter value in Basic search type only.
	*/
	Post *string

	/* Q.

	   Use for search value in fluent mode.  When passed as only param, fluent search type is assumed.
	*/
	Q *string

	/* Street.

	   Street value search value in Basic search type only.
	*/
	Street *string

	/* Type.

	   Search type to be used in request.  Possible values are basic, advanced, attribute or fluent.  Search request defaults to fluent (single line) if not provided.
	*/
	Type string

	/* Value.

	   Value for filter expression.  Used in combination with key and op params.  Only used for Advanced and Attribute search types.
	*/
	Value *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the constituents search params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsSearchParams) WithDefaults() *ConstituentsSearchParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the constituents search params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *ConstituentsSearchParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the constituents search params
func (o *ConstituentsSearchParams) WithTimeout(timeout time.Duration) *ConstituentsSearchParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the constituents search params
func (o *ConstituentsSearchParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the constituents search params
func (o *ConstituentsSearchParams) WithContext(ctx context.Context) *ConstituentsSearchParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the constituents search params
func (o *ConstituentsSearchParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the constituents search params
func (o *ConstituentsSearchParams) WithHTTPClient(client *http.Client) *ConstituentsSearchParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the constituents search params
func (o *ConstituentsSearchParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAtype adds the atype to the constituents search params
func (o *ConstituentsSearchParams) WithAtype(atype *string) *ConstituentsSearchParams {
	o.SetAtype(atype)
	return o
}

// SetAtype adds the atype to the constituents search params
func (o *ConstituentsSearchParams) SetAtype(atype *string) {
	o.Atype = atype
}

// WithConstituencyIds adds the constituencyIds to the constituents search params
func (o *ConstituentsSearchParams) WithConstituencyIds(constituencyIds *string) *ConstituentsSearchParams {
	o.SetConstituencyIds(constituencyIds)
	return o
}

// SetConstituencyIds adds the constituencyIds to the constituents search params
func (o *ConstituentsSearchParams) SetConstituencyIds(constituencyIds *string) {
	o.ConstituencyIds = constituencyIds
}

// WithConstituentGroups adds the constituentGroups to the constituents search params
func (o *ConstituentsSearchParams) WithConstituentGroups(constituentGroups *string) *ConstituentsSearchParams {
	o.SetConstituentGroups(constituentGroups)
	return o
}

// SetConstituentGroups adds the constituentGroups to the constituents search params
func (o *ConstituentsSearchParams) SetConstituentGroups(constituentGroups *string) {
	o.ConstituentGroups = constituentGroups
}

// WithConstituentID adds the constituentID to the constituents search params
func (o *ConstituentsSearchParams) WithConstituentID(constituentID *string) *ConstituentsSearchParams {
	o.SetConstituentID(constituentID)
	return o
}

// SetConstituentID adds the constituentId to the constituents search params
func (o *ConstituentsSearchParams) SetConstituentID(constituentID *string) {
	o.ConstituentID = constituentID
}

// WithDup adds the dup to the constituents search params
func (o *ConstituentsSearchParams) WithDup(dup *string) *ConstituentsSearchParams {
	o.SetDup(dup)
	return o
}

// SetDup adds the dup to the constituents search params
func (o *ConstituentsSearchParams) SetDup(dup *string) {
	o.Dup = dup
}

// WithFn adds the fn to the constituents search params
func (o *ConstituentsSearchParams) WithFn(fn *string) *ConstituentsSearchParams {
	o.SetFn(fn)
	return o
}

// SetFn adds the fn to the constituents search params
func (o *ConstituentsSearchParams) SetFn(fn *string) {
	o.Fn = fn
}

// WithIncludeAffiliates adds the includeAffiliates to the constituents search params
func (o *ConstituentsSearchParams) WithIncludeAffiliates(includeAffiliates *string) *ConstituentsSearchParams {
	o.SetIncludeAffiliates(includeAffiliates)
	return o
}

// SetIncludeAffiliates adds the includeAffiliates to the constituents search params
func (o *ConstituentsSearchParams) SetIncludeAffiliates(includeAffiliates *string) {
	o.IncludeAffiliates = includeAffiliates
}

// WithKey adds the key to the constituents search params
func (o *ConstituentsSearchParams) WithKey(key *string) *ConstituentsSearchParams {
	o.SetKey(key)
	return o
}

// SetKey adds the key to the constituents search params
func (o *ConstituentsSearchParams) SetKey(key *string) {
	o.Key = key
}

// WithListID adds the listID to the constituents search params
func (o *ConstituentsSearchParams) WithListID(listID *string) *ConstituentsSearchParams {
	o.SetListID(listID)
	return o
}

// SetListID adds the listId to the constituents search params
func (o *ConstituentsSearchParams) SetListID(listID *string) {
	o.ListID = listID
}

// WithLn adds the ln to the constituents search params
func (o *ConstituentsSearchParams) WithLn(ln *string) *ConstituentsSearchParams {
	o.SetLn(ln)
	return o
}

// SetLn adds the ln to the constituents search params
func (o *ConstituentsSearchParams) SetLn(ln *string) {
	o.Ln = ln
}

// WithOp adds the op to the constituents search params
func (o *ConstituentsSearchParams) WithOp(op *string) *ConstituentsSearchParams {
	o.SetOp(op)
	return o
}

// SetOp adds the op to the constituents search params
func (o *ConstituentsSearchParams) SetOp(op *string) {
	o.Op = op
}

// WithPage adds the page to the constituents search params
func (o *ConstituentsSearchParams) WithPage(page *string) *ConstituentsSearchParams {
	o.SetPage(page)
	return o
}

// SetPage adds the page to the constituents search params
func (o *ConstituentsSearchParams) SetPage(page *string) {
	o.Page = page
}

// WithPageSize adds the pageSize to the constituents search params
func (o *ConstituentsSearchParams) WithPageSize(pageSize *string) *ConstituentsSearchParams {
	o.SetPageSize(pageSize)
	return o
}

// SetPageSize adds the pageSize to the constituents search params
func (o *ConstituentsSearchParams) SetPageSize(pageSize *string) {
	o.PageSize = pageSize
}

// WithPost adds the post to the constituents search params
func (o *ConstituentsSearchParams) WithPost(post *string) *ConstituentsSearchParams {
	o.SetPost(post)
	return o
}

// SetPost adds the post to the constituents search params
func (o *ConstituentsSearchParams) SetPost(post *string) {
	o.Post = post
}

// WithQ adds the q to the constituents search params
func (o *ConstituentsSearchParams) WithQ(q *string) *ConstituentsSearchParams {
	o.SetQ(q)
	return o
}

// SetQ adds the q to the constituents search params
func (o *ConstituentsSearchParams) SetQ(q *string) {
	o.Q = q
}

// WithStreet adds the street to the constituents search params
func (o *ConstituentsSearchParams) WithStreet(street *string) *ConstituentsSearchParams {
	o.SetStreet(street)
	return o
}

// SetStreet adds the street to the constituents search params
func (o *ConstituentsSearchParams) SetStreet(street *string) {
	o.Street = street
}

// WithType adds the typeVar to the constituents search params
func (o *ConstituentsSearchParams) WithType(typeVar string) *ConstituentsSearchParams {
	o.SetType(typeVar)
	return o
}

// SetType adds the type to the constituents search params
func (o *ConstituentsSearchParams) SetType(typeVar string) {
	o.Type = typeVar
}

// WithValue adds the value to the constituents search params
func (o *ConstituentsSearchParams) WithValue(value *string) *ConstituentsSearchParams {
	o.SetValue(value)
	return o
}

// SetValue adds the value to the constituents search params
func (o *ConstituentsSearchParams) SetValue(value *string) {
	o.Value = value
}

// WriteToRequest writes these params to a swagger request
func (o *ConstituentsSearchParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Atype != nil {

		// query param atype
		var qrAtype string

		if o.Atype != nil {
			qrAtype = *o.Atype
		}
		qAtype := qrAtype
		if qAtype != "" {

			if err := r.SetQueryParam("atype", qAtype); err != nil {
				return err
			}
		}
	}

	if o.ConstituencyIds != nil {

		// query param constituencyIds
		var qrConstituencyIds string

		if o.ConstituencyIds != nil {
			qrConstituencyIds = *o.ConstituencyIds
		}
		qConstituencyIds := qrConstituencyIds
		if qConstituencyIds != "" {

			if err := r.SetQueryParam("constituencyIds", qConstituencyIds); err != nil {
				return err
			}
		}
	}

	if o.ConstituentGroups != nil {

		// query param constituentGroups
		var qrConstituentGroups string

		if o.ConstituentGroups != nil {
			qrConstituentGroups = *o.ConstituentGroups
		}
		qConstituentGroups := qrConstituentGroups
		if qConstituentGroups != "" {

			if err := r.SetQueryParam("constituentGroups", qConstituentGroups); err != nil {
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

	if o.Dup != nil {

		// query param dup
		var qrDup string

		if o.Dup != nil {
			qrDup = *o.Dup
		}
		qDup := qrDup
		if qDup != "" {

			if err := r.SetQueryParam("dup", qDup); err != nil {
				return err
			}
		}
	}

	if o.Fn != nil {

		// query param fn
		var qrFn string

		if o.Fn != nil {
			qrFn = *o.Fn
		}
		qFn := qrFn
		if qFn != "" {

			if err := r.SetQueryParam("fn", qFn); err != nil {
				return err
			}
		}
	}

	if o.IncludeAffiliates != nil {

		// query param includeAffiliates
		var qrIncludeAffiliates string

		if o.IncludeAffiliates != nil {
			qrIncludeAffiliates = *o.IncludeAffiliates
		}
		qIncludeAffiliates := qrIncludeAffiliates
		if qIncludeAffiliates != "" {

			if err := r.SetQueryParam("includeAffiliates", qIncludeAffiliates); err != nil {
				return err
			}
		}
	}

	if o.Key != nil {

		// query param key
		var qrKey string

		if o.Key != nil {
			qrKey = *o.Key
		}
		qKey := qrKey
		if qKey != "" {

			if err := r.SetQueryParam("key", qKey); err != nil {
				return err
			}
		}
	}

	if o.ListID != nil {

		// query param listId
		var qrListID string

		if o.ListID != nil {
			qrListID = *o.ListID
		}
		qListID := qrListID
		if qListID != "" {

			if err := r.SetQueryParam("listId", qListID); err != nil {
				return err
			}
		}
	}

	if o.Ln != nil {

		// query param ln
		var qrLn string

		if o.Ln != nil {
			qrLn = *o.Ln
		}
		qLn := qrLn
		if qLn != "" {

			if err := r.SetQueryParam("ln", qLn); err != nil {
				return err
			}
		}
	}

	if o.Op != nil {

		// query param op
		var qrOp string

		if o.Op != nil {
			qrOp = *o.Op
		}
		qOp := qrOp
		if qOp != "" {

			if err := r.SetQueryParam("op", qOp); err != nil {
				return err
			}
		}
	}

	if o.Page != nil {

		// query param page
		var qrPage string

		if o.Page != nil {
			qrPage = *o.Page
		}
		qPage := qrPage
		if qPage != "" {

			if err := r.SetQueryParam("page", qPage); err != nil {
				return err
			}
		}
	}

	if o.PageSize != nil {

		// query param pageSize
		var qrPageSize string

		if o.PageSize != nil {
			qrPageSize = *o.PageSize
		}
		qPageSize := qrPageSize
		if qPageSize != "" {

			if err := r.SetQueryParam("pageSize", qPageSize); err != nil {
				return err
			}
		}
	}

	if o.Post != nil {

		// query param post
		var qrPost string

		if o.Post != nil {
			qrPost = *o.Post
		}
		qPost := qrPost
		if qPost != "" {

			if err := r.SetQueryParam("post", qPost); err != nil {
				return err
			}
		}
	}

	if o.Q != nil {

		// query param q
		var qrQ string

		if o.Q != nil {
			qrQ = *o.Q
		}
		qQ := qrQ
		if qQ != "" {

			if err := r.SetQueryParam("q", qQ); err != nil {
				return err
			}
		}
	}

	if o.Street != nil {

		// query param street
		var qrStreet string

		if o.Street != nil {
			qrStreet = *o.Street
		}
		qStreet := qrStreet
		if qStreet != "" {

			if err := r.SetQueryParam("street", qStreet); err != nil {
				return err
			}
		}
	}

	// query param type
	qrType := o.Type
	qType := qrType
	if qType != "" {

		if err := r.SetQueryParam("type", qType); err != nil {
			return err
		}
	}

	if o.Value != nil {

		// query param value
		var qrValue string

		if o.Value != nil {
			qrValue = *o.Value
		}
		qValue := qrValue
		if qValue != "" {

			if err := r.SetQueryParam("value", qValue); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}