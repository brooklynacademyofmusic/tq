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

// PaymentTypesGetSummariesReader is a Reader for the PaymentTypesGetSummaries structure.
type PaymentTypesGetSummariesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PaymentTypesGetSummariesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPaymentTypesGetSummariesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPaymentTypesGetSummariesDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPaymentTypesGetSummariesOK creates a PaymentTypesGetSummariesOK with default headers values
func NewPaymentTypesGetSummariesOK() *PaymentTypesGetSummariesOK {
	return &PaymentTypesGetSummariesOK{}
}

/*
PaymentTypesGetSummariesOK describes a response with status code 200, with default header values.

OK
*/
type PaymentTypesGetSummariesOK struct {
	Payload []*models.PaymentTypeSummary
}

// IsSuccess returns true when this payment types get summaries o k response has a 2xx status code
func (o *PaymentTypesGetSummariesOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this payment types get summaries o k response has a 3xx status code
func (o *PaymentTypesGetSummariesOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this payment types get summaries o k response has a 4xx status code
func (o *PaymentTypesGetSummariesOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this payment types get summaries o k response has a 5xx status code
func (o *PaymentTypesGetSummariesOK) IsServerError() bool {
	return false
}

// IsCode returns true when this payment types get summaries o k response a status code equal to that given
func (o *PaymentTypesGetSummariesOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the payment types get summaries o k response
func (o *PaymentTypesGetSummariesOK) Code() int {
	return 200
}

func (o *PaymentTypesGetSummariesOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentTypes/Summary][%d] paymentTypesGetSummariesOK %s", 200, payload)
}

func (o *PaymentTypesGetSummariesOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentTypes/Summary][%d] paymentTypesGetSummariesOK %s", 200, payload)
}

func (o *PaymentTypesGetSummariesOK) GetPayload() []*models.PaymentTypeSummary {
	return o.Payload
}

func (o *PaymentTypesGetSummariesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPaymentTypesGetSummariesDefault creates a PaymentTypesGetSummariesDefault with default headers values
func NewPaymentTypesGetSummariesDefault(code int) *PaymentTypesGetSummariesDefault {
	return &PaymentTypesGetSummariesDefault{
		_statusCode: code,
	}
}

/*
PaymentTypesGetSummariesDefault describes a response with status code -1, with default header values.

Error
*/
type PaymentTypesGetSummariesDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this payment types get summaries default response has a 2xx status code
func (o *PaymentTypesGetSummariesDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this payment types get summaries default response has a 3xx status code
func (o *PaymentTypesGetSummariesDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this payment types get summaries default response has a 4xx status code
func (o *PaymentTypesGetSummariesDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this payment types get summaries default response has a 5xx status code
func (o *PaymentTypesGetSummariesDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this payment types get summaries default response a status code equal to that given
func (o *PaymentTypesGetSummariesDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the payment types get summaries default response
func (o *PaymentTypesGetSummariesDefault) Code() int {
	return o._statusCode
}

func (o *PaymentTypesGetSummariesDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentTypes/Summary][%d] PaymentTypes_GetSummaries default %s", o._statusCode, payload)
}

func (o *PaymentTypesGetSummariesDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/PaymentTypes/Summary][%d] PaymentTypes_GetSummaries default %s", o._statusCode, payload)
}

func (o *PaymentTypesGetSummariesDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PaymentTypesGetSummariesDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
