// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// PricingRuleCategoriesGetSummariesReader is a Reader for the PricingRuleCategoriesGetSummaries structure.
type PricingRuleCategoriesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PricingRuleCategoriesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPricingRuleCategoriesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/PricingRuleCategories/Summary] PricingRuleCategories_GetSummaries", response, response.Code())
	}
}

// NewPricingRuleCategoriesGetSummariesOK creates a PricingRuleCategoriesGetSummariesOK with default headers values
func NewPricingRuleCategoriesGetSummariesOK() *PricingRuleCategoriesGetSummariesOK {
	return &PricingRuleCategoriesGetSummariesOK{}
}

/*
PricingRuleCategoriesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type PricingRuleCategoriesGetSummariesOK struct {
	Payload []*models.PricingRuleCategorySummary
}

// IsSuccess returns true when this pricing rule categories get summaries o k response has a 2xx status code
func (o *PricingRuleCategoriesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this pricing rule categories get summaries o k response has a 3xx status code
func (o *PricingRuleCategoriesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this pricing rule categories get summaries o k response has a 4xx status code
func (o *PricingRuleCategoriesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this pricing rule categories get summaries o k response has a 5xx status code
func (o *PricingRuleCategoriesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this pricing rule categories get summaries o k response a status code equal to that given
func (o *PricingRuleCategoriesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the pricing rule categories get summaries o k response
func (o *PricingRuleCategoriesGetSummariesOK) Code() int {
	return 200
}

func (o *PricingRuleCategoriesGetSummariesOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleCategories/Summary][%d] pricingRuleCategoriesGetSummariesOK  %+v", 200, o.Payload)
}

func (o *PricingRuleCategoriesGetSummariesOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/PricingRuleCategories/Summary][%d] pricingRuleCategoriesGetSummariesOK  %+v", 200, o.Payload)
}

func (o *PricingRuleCategoriesGetSummariesOK) GetPayload() []*models.PricingRuleCategorySummary {
	return o.Payload
}

func (o *PricingRuleCategoriesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}