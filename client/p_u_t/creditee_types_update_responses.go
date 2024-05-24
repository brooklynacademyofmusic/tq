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

// CrediteeTypesUpdateReader is a Reader for the CrediteeTypesUpdate structure.
type CrediteeTypesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CrediteeTypesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCrediteeTypesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCrediteeTypesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCrediteeTypesUpdateOK creates a CrediteeTypesUpdateOK with default headers values
func NewCrediteeTypesUpdateOK() *CrediteeTypesUpdateOK {
	return &CrediteeTypesUpdateOK{}
}

/*
CrediteeTypesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type CrediteeTypesUpdateOK struct {
	Payload *models.CrediteeType
}

// IsSuccess returns true when this creditee types update o k response has a 2xx status code
func (o *CrediteeTypesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this creditee types update o k response has a 3xx status code
func (o *CrediteeTypesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this creditee types update o k response has a 4xx status code
func (o *CrediteeTypesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this creditee types update o k response has a 5xx status code
func (o *CrediteeTypesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this creditee types update o k response a status code equal to that given
func (o *CrediteeTypesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the creditee types update o k response
func (o *CrediteeTypesUpdateOK) Code() int {
	return 200
}

func (o *CrediteeTypesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CrediteeTypes/{id}][%d] crediteeTypesUpdateOK %s", 200, payload)
}

func (o *CrediteeTypesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CrediteeTypes/{id}][%d] crediteeTypesUpdateOK %s", 200, payload)
}

func (o *CrediteeTypesUpdateOK) GetPayload() *models.CrediteeType {
	return o.Payload
}

func (o *CrediteeTypesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.CrediteeType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCrediteeTypesUpdateDefault creates a CrediteeTypesUpdateDefault with default headers values
func NewCrediteeTypesUpdateDefault(code int) *CrediteeTypesUpdateDefault {
	return &CrediteeTypesUpdateDefault{
		_statusCode: code,
	}
}

/*
CrediteeTypesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type CrediteeTypesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this creditee types update default response has a 2xx status code
func (o *CrediteeTypesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this creditee types update default response has a 3xx status code
func (o *CrediteeTypesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this creditee types update default response has a 4xx status code
func (o *CrediteeTypesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this creditee types update default response has a 5xx status code
func (o *CrediteeTypesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this creditee types update default response a status code equal to that given
func (o *CrediteeTypesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the creditee types update default response
func (o *CrediteeTypesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *CrediteeTypesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CrediteeTypes/{id}][%d] CrediteeTypes_Update default %s", o._statusCode, payload)
}

func (o *CrediteeTypesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/CrediteeTypes/{id}][%d] CrediteeTypes_Update default %s", o._statusCode, payload)
}

func (o *CrediteeTypesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CrediteeTypesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
