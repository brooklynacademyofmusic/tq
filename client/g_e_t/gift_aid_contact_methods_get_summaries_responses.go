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

// GiftAidContactMethodsGetSummariesReader is a Reader for the GiftAidContactMethodsGetSummaries structure.
type GiftAidContactMethodsGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GiftAidContactMethodsGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGiftAidContactMethodsGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGiftAidContactMethodsGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGiftAidContactMethodsGetSummariesOK creates a GiftAidContactMethodsGetSummariesOK with default headers values
func NewGiftAidContactMethodsGetSummariesOK() *GiftAidContactMethodsGetSummariesOK {
	return &GiftAidContactMethodsGetSummariesOK{}
}

/*
GiftAidContactMethodsGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type GiftAidContactMethodsGetSummariesOK struct {
	Payload []*models.GiftAidContactMethodSummary
}

// IsSuccess returns true when this gift aid contact methods get summaries o k response has a 2xx status code
func (o *GiftAidContactMethodsGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gift aid contact methods get summaries o k response has a 3xx status code
func (o *GiftAidContactMethodsGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gift aid contact methods get summaries o k response has a 4xx status code
func (o *GiftAidContactMethodsGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gift aid contact methods get summaries o k response has a 5xx status code
func (o *GiftAidContactMethodsGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gift aid contact methods get summaries o k response a status code equal to that given
func (o *GiftAidContactMethodsGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the gift aid contact methods get summaries o k response
func (o *GiftAidContactMethodsGetSummariesOK) Code() int {
	return 200
}

func (o *GiftAidContactMethodsGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidContactMethods/Summary][%d] giftAidContactMethodsGetSummariesOK %s", 200, payload)
}

func (o *GiftAidContactMethodsGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidContactMethods/Summary][%d] giftAidContactMethodsGetSummariesOK %s", 200, payload)
}

func (o *GiftAidContactMethodsGetSummariesOK) GetPayload() []*models.GiftAidContactMethodSummary {
	return o.Payload
}

func (o *GiftAidContactMethodsGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGiftAidContactMethodsGetSummariesDefault creates a GiftAidContactMethodsGetSummariesDefault with default headers values
func NewGiftAidContactMethodsGetSummariesDefault(code int) *GiftAidContactMethodsGetSummariesDefault {
	return &GiftAidContactMethodsGetSummariesDefault{
		_statusCode: code,
	}
}

/*
GiftAidContactMethodsGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type GiftAidContactMethodsGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this gift aid contact methods get summaries default response has a 2xx status code
func (o *GiftAidContactMethodsGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this gift aid contact methods get summaries default response has a 3xx status code
func (o *GiftAidContactMethodsGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this gift aid contact methods get summaries default response has a 4xx status code
func (o *GiftAidContactMethodsGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this gift aid contact methods get summaries default response has a 5xx status code
func (o *GiftAidContactMethodsGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this gift aid contact methods get summaries default response a status code equal to that given
func (o *GiftAidContactMethodsGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the gift aid contact methods get summaries default response
func (o *GiftAidContactMethodsGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *GiftAidContactMethodsGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidContactMethods/Summary][%d] GiftAidContactMethods_GetSummaries default %s", o._statusCode, payload)
}

func (o *GiftAidContactMethodsGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidContactMethods/Summary][%d] GiftAidContactMethods_GetSummaries default %s", o._statusCode, payload)
}

func (o *GiftAidContactMethodsGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GiftAidContactMethodsGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}