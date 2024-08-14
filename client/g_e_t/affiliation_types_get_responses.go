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

// AffiliationTypesGetReader is a Reader for the AffiliationTypesGet structure.
type AffiliationTypesGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AffiliationTypesGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewAffiliationTypesGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAffiliationTypesGetDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAffiliationTypesGetOK creates a AffiliationTypesGetOK with default headers values
func NewAffiliationTypesGetOK() *AffiliationTypesGetOK {
	return &AffiliationTypesGetOK{}
}

/*
AffiliationTypesGetOK describes a response with status code 200, with default header values.

OK
*/
type AffiliationTypesGetOK struct {
	Payload *models.AffiliationType
}

// IsSuccess returns true when this affiliation types get o k response has a 2xx status code
func (o *AffiliationTypesGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this affiliation types get o k response has a 3xx status code
func (o *AffiliationTypesGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this affiliation types get o k response has a 4xx status code
func (o *AffiliationTypesGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this affiliation types get o k response has a 5xx status code
func (o *AffiliationTypesGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this affiliation types get o k response a status code equal to that given
func (o *AffiliationTypesGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the affiliation types get o k response
func (o *AffiliationTypesGetOK) Code() int {
	return 200
}

func (o *AffiliationTypesGetOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AffiliationTypes/{id}][%d] affiliationTypesGetOK %s", 200, payload)
}

func (o *AffiliationTypesGetOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AffiliationTypes/{id}][%d] affiliationTypesGetOK %s", 200, payload)
}

func (o *AffiliationTypesGetOK) GetPayload() *models.AffiliationType {
	return o.Payload
}

func (o *AffiliationTypesGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AffiliationType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewAffiliationTypesGetDefault creates a AffiliationTypesGetDefault with default headers values
func NewAffiliationTypesGetDefault(code int) *AffiliationTypesGetDefault {
	return &AffiliationTypesGetDefault{
		_statusCode: code,
	}
}

/*
AffiliationTypesGetDefault describes a response with status code -1, with default header values.

Error
*/
type AffiliationTypesGetDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this affiliation types get default response has a 2xx status code
func (o *AffiliationTypesGetDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this affiliation types get default response has a 3xx status code
func (o *AffiliationTypesGetDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this affiliation types get default response has a 4xx status code
func (o *AffiliationTypesGetDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this affiliation types get default response has a 5xx status code
func (o *AffiliationTypesGetDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this affiliation types get default response a status code equal to that given
func (o *AffiliationTypesGetDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the affiliation types get default response
func (o *AffiliationTypesGetDefault) Code() int {
	return o._statusCode
}

func (o *AffiliationTypesGetDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AffiliationTypes/{id}][%d] AffiliationTypes_Get default %s", o._statusCode, payload)
}

func (o *AffiliationTypesGetDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/AffiliationTypes/{id}][%d] AffiliationTypes_Get default %s", o._statusCode, payload)
}

func (o *AffiliationTypesGetDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AffiliationTypesGetDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}