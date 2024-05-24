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

// GiftAidRatesUpdateReader is a Reader for the GiftAidRatesUpdate structure.
type GiftAidRatesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GiftAidRatesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGiftAidRatesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGiftAidRatesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGiftAidRatesUpdateOK creates a GiftAidRatesUpdateOK with default headers values
func NewGiftAidRatesUpdateOK() *GiftAidRatesUpdateOK {
	return &GiftAidRatesUpdateOK{}
}

/*
GiftAidRatesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type GiftAidRatesUpdateOK struct {
	Payload *models.GiftAidRate
}

// IsSuccess returns true when this gift aid rates update o k response has a 2xx status code
func (o *GiftAidRatesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gift aid rates update o k response has a 3xx status code
func (o *GiftAidRatesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gift aid rates update o k response has a 4xx status code
func (o *GiftAidRatesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gift aid rates update o k response has a 5xx status code
func (o *GiftAidRatesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gift aid rates update o k response a status code equal to that given
func (o *GiftAidRatesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the gift aid rates update o k response
func (o *GiftAidRatesUpdateOK) Code() int {
	return 200
}

func (o *GiftAidRatesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidRates/{id}][%d] giftAidRatesUpdateOK %s", 200, payload)
}

func (o *GiftAidRatesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidRates/{id}][%d] giftAidRatesUpdateOK %s", 200, payload)
}

func (o *GiftAidRatesUpdateOK) GetPayload() *models.GiftAidRate {
	return o.Payload
}

func (o *GiftAidRatesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GiftAidRate)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGiftAidRatesUpdateDefault creates a GiftAidRatesUpdateDefault with default headers values
func NewGiftAidRatesUpdateDefault(code int) *GiftAidRatesUpdateDefault {
	return &GiftAidRatesUpdateDefault{
		_statusCode: code,
	}
}

/*
GiftAidRatesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type GiftAidRatesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this gift aid rates update default response has a 2xx status code
func (o *GiftAidRatesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this gift aid rates update default response has a 3xx status code
func (o *GiftAidRatesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this gift aid rates update default response has a 4xx status code
func (o *GiftAidRatesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this gift aid rates update default response has a 5xx status code
func (o *GiftAidRatesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this gift aid rates update default response a status code equal to that given
func (o *GiftAidRatesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the gift aid rates update default response
func (o *GiftAidRatesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *GiftAidRatesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidRates/{id}][%d] GiftAidRates_Update default %s", o._statusCode, payload)
}

func (o *GiftAidRatesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidRates/{id}][%d] GiftAidRates_Update default %s", o._statusCode, payload)
}

func (o *GiftAidRatesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GiftAidRatesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
