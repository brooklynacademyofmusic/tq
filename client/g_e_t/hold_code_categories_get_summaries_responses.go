// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// HoldCodeCategoriesGetSummariesReader is a Reader for the HoldCodeCategoriesGetSummaries structure.
type HoldCodeCategoriesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *HoldCodeCategoriesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewHoldCodeCategoriesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewHoldCodeCategoriesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewHoldCodeCategoriesGetSummariesOK creates a HoldCodeCategoriesGetSummariesOK with default headers values
func NewHoldCodeCategoriesGetSummariesOK() *HoldCodeCategoriesGetSummariesOK {
	return &HoldCodeCategoriesGetSummariesOK{}
}

/*
HoldCodeCategoriesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type HoldCodeCategoriesGetSummariesOK struct {
	Payload []*models.HoldCodeCategorySummary
}

// IsSuccess returns true when this hold code categories get summaries o k response has a 2xx status code
func (o *HoldCodeCategoriesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this hold code categories get summaries o k response has a 3xx status code
func (o *HoldCodeCategoriesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this hold code categories get summaries o k response has a 4xx status code
func (o *HoldCodeCategoriesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this hold code categories get summaries o k response has a 5xx status code
func (o *HoldCodeCategoriesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this hold code categories get summaries o k response a status code equal to that given
func (o *HoldCodeCategoriesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the hold code categories get summaries o k response
func (o *HoldCodeCategoriesGetSummariesOK) Code() int {
	return 200
}

func (o *HoldCodeCategoriesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/HoldCodeCategories/Summary][%d] holdCodeCategoriesGetSummariesOK %s", 200, payload)
}

func (o *HoldCodeCategoriesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/HoldCodeCategories/Summary][%d] holdCodeCategoriesGetSummariesOK %s", 200, payload)
}

func (o *HoldCodeCategoriesGetSummariesOK) GetPayload() []*models.HoldCodeCategorySummary {
	return o.Payload
}

func (o *HoldCodeCategoriesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewHoldCodeCategoriesGetSummariesDefault creates a HoldCodeCategoriesGetSummariesDefault with default headers values
func NewHoldCodeCategoriesGetSummariesDefault(code int) *HoldCodeCategoriesGetSummariesDefault {
	return &HoldCodeCategoriesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
HoldCodeCategoriesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type HoldCodeCategoriesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this hold code categories get summaries default response has a 2xx status code
func (o *HoldCodeCategoriesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this hold code categories get summaries default response has a 3xx status code
func (o *HoldCodeCategoriesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this hold code categories get summaries default response has a 4xx status code
func (o *HoldCodeCategoriesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this hold code categories get summaries default response has a 5xx status code
func (o *HoldCodeCategoriesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this hold code categories get summaries default response a status code equal to that given
func (o *HoldCodeCategoriesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the hold code categories get summaries default response
func (o *HoldCodeCategoriesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *HoldCodeCategoriesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/HoldCodeCategories/Summary][%d] HoldCodeCategories_GetSummaries default %s", o._statusCode, payload)
}

func (o *HoldCodeCategoriesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/HoldCodeCategories/Summary][%d] HoldCodeCategories_GetSummaries default %s", o._statusCode, payload)
}

func (o *HoldCodeCategoriesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *HoldCodeCategoriesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
