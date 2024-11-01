// Code generated by go-swagger; DO NOT EDIT.

package p_u_t

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

// CurrencyTypesUpdateReader is a Reader for the CurrencyTypesUpdate structure.
type CurrencyTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CurrencyTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCurrencyTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCurrencyTypesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCurrencyTypesUpdateOK creates a CurrencyTypesUpdateOK with default headers values
func NewCurrencyTypesUpdateOK() *CurrencyTypesUpdateOK {
	return &CurrencyTypesUpdateOK{}
}

/*
CurrencyTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type CurrencyTypesUpdateOK struct {
	Payload *models.CurrencyType
}

// IsSuccess returns true when this currency types update o k response has a 2xx status code
func (o *CurrencyTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this currency types update o k response has a 3xx status code
func (o *CurrencyTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this currency types update o k response has a 4xx status code
func (o *CurrencyTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this currency types update o k response has a 5xx status code
func (o *CurrencyTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this currency types update o k response a status code equal to that given
func (o *CurrencyTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the currency types update o k response
func (o *CurrencyTypesUpdateOK) Code() int {
	return 200
}

func (o *CurrencyTypesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CurrencyTypes/{id}][%d] currencyTypesUpdateOK %s", 200, payload)
}

func (o *CurrencyTypesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CurrencyTypes/{id}][%d] currencyTypesUpdateOK %s", 200, payload)
}

func (o *CurrencyTypesUpdateOK) GetPayload() *models.CurrencyType {
	return o.Payload
}

func (o *CurrencyTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CurrencyType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCurrencyTypesUpdateDefault creates a CurrencyTypesUpdateDefault with default headers values
func NewCurrencyTypesUpdateDefault(code int) *CurrencyTypesUpdateDefault {
	return &CurrencyTypesUpdateDefault{
		_statusCode: code,
	}
}

/*
CurrencyTypesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type CurrencyTypesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this currency types update default response has a 2xx status code
func (o *CurrencyTypesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this currency types update default response has a 3xx status code
func (o *CurrencyTypesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this currency types update default response has a 4xx status code
func (o *CurrencyTypesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this currency types update default response has a 5xx status code
func (o *CurrencyTypesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this currency types update default response a status code equal to that given
func (o *CurrencyTypesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the currency types update default response
func (o *CurrencyTypesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *CurrencyTypesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CurrencyTypes/{id}][%d] CurrencyTypes_Update default %s", o._statusCode, payload)
}

func (o *CurrencyTypesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CurrencyTypes/{id}][%d] CurrencyTypes_Update default %s", o._statusCode, payload)
}

func (o *CurrencyTypesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CurrencyTypesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}