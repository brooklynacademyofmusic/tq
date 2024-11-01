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

// GiftAidTypesGetReader is a Reader for the GiftAidTypesGet structure.
type GiftAidTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GiftAidTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGiftAidTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGiftAidTypesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGiftAidTypesGetOK creates a GiftAidTypesGetOK with default headers values
func NewGiftAidTypesGetOK() *GiftAidTypesGetOK {
	return &GiftAidTypesGetOK{}
}

/*
GiftAidTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type GiftAidTypesGetOK struct {
	Payload *models.GiftAidType
}

// IsSuccess returns true when this gift aid types get o k response has a 2xx status code
func (o *GiftAidTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gift aid types get o k response has a 3xx status code
func (o *GiftAidTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gift aid types get o k response has a 4xx status code
func (o *GiftAidTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gift aid types get o k response has a 5xx status code
func (o *GiftAidTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gift aid types get o k response a status code equal to that given
func (o *GiftAidTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the gift aid types get o k response
func (o *GiftAidTypesGetOK) Code() int {
	return 200
}

func (o *GiftAidTypesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidTypes/{id}][%d] giftAidTypesGetOK %s", 200, payload)
}

func (o *GiftAidTypesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidTypes/{id}][%d] giftAidTypesGetOK %s", 200, payload)
}

func (o *GiftAidTypesGetOK) GetPayload() *models.GiftAidType {
	return o.Payload
}

func (o *GiftAidTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GiftAidType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGiftAidTypesGetDefault creates a GiftAidTypesGetDefault with default headers values
func NewGiftAidTypesGetDefault(code int) *GiftAidTypesGetDefault {
	return &GiftAidTypesGetDefault{
		_statusCode: code,
	}
}

/*
GiftAidTypesGetDefault describes a response with status code -1, with default header values.

Error
*/
type GiftAidTypesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this gift aid types get default response has a 2xx status code
func (o *GiftAidTypesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this gift aid types get default response has a 3xx status code
func (o *GiftAidTypesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this gift aid types get default response has a 4xx status code
func (o *GiftAidTypesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this gift aid types get default response has a 5xx status code
func (o *GiftAidTypesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this gift aid types get default response a status code equal to that given
func (o *GiftAidTypesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the gift aid types get default response
func (o *GiftAidTypesGetDefault) Code() int {
	return o._statusCode
}

func (o *GiftAidTypesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidTypes/{id}][%d] GiftAidTypes_Get default %s", o._statusCode, payload)
}

func (o *GiftAidTypesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/GiftAidTypes/{id}][%d] GiftAidTypes_Get default %s", o._statusCode, payload)
}

func (o *GiftAidTypesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GiftAidTypesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}