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

// CountriesGetAllReader is a Reader for the CountriesGetAll structure.
type CountriesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CountriesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCountriesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCountriesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCountriesGetAllOK creates a CountriesGetAllOK with default headers values
func NewCountriesGetAllOK() *CountriesGetAllOK {
	return &CountriesGetAllOK{}
}

/*
CountriesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type CountriesGetAllOK struct {
	Payload []*models.Country
}

// IsSuccess returns true when this countries get all o k response has a 2xx status code
func (o *CountriesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this countries get all o k response has a 3xx status code
func (o *CountriesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this countries get all o k response has a 4xx status code
func (o *CountriesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this countries get all o k response has a 5xx status code
func (o *CountriesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this countries get all o k response a status code equal to that given
func (o *CountriesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the countries get all o k response
func (o *CountriesGetAllOK) Code() int {
	return 200
}

func (o *CountriesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Countries][%d] countriesGetAllOK %s", 200, payload)
}

func (o *CountriesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Countries][%d] countriesGetAllOK %s", 200, payload)
}

func (o *CountriesGetAllOK) GetPayload() []*models.Country {
	return o.Payload
}

func (o *CountriesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCountriesGetAllDefault creates a CountriesGetAllDefault with default headers values
func NewCountriesGetAllDefault(code int) *CountriesGetAllDefault {
	return &CountriesGetAllDefault{
		_statusCode: code,
	}
}

/*
CountriesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type CountriesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this countries get all default response has a 2xx status code
func (o *CountriesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this countries get all default response has a 3xx status code
func (o *CountriesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this countries get all default response has a 4xx status code
func (o *CountriesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this countries get all default response has a 5xx status code
func (o *CountriesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this countries get all default response a status code equal to that given
func (o *CountriesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the countries get all default response
func (o *CountriesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *CountriesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Countries][%d] Countries_GetAll default %s", o._statusCode, payload)
}

func (o *CountriesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/Countries][%d] Countries_GetAll default %s", o._statusCode, payload)
}

func (o *CountriesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CountriesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
