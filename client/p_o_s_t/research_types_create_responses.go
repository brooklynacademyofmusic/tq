// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

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

// ResearchTypesCreateReader is a Reader for the ResearchTypesCreate structure.
type ResearchTypesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResearchTypesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewResearchTypesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResearchTypesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResearchTypesCreateOK creates a ResearchTypesCreateOK with default headers values
func NewResearchTypesCreateOK() *ResearchTypesCreateOK {
	return &ResearchTypesCreateOK{}
}

/*
ResearchTypesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ResearchTypesCreateOK struct {
	Payload *models.ResearchType
}

// IsSuccess returns true when this research types create o k response has a 2xx status code
func (o *ResearchTypesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this research types create o k response has a 3xx status code
func (o *ResearchTypesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this research types create o k response has a 4xx status code
func (o *ResearchTypesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this research types create o k response has a 5xx status code
func (o *ResearchTypesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this research types create o k response a status code equal to that given
func (o *ResearchTypesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the research types create o k response
func (o *ResearchTypesCreateOK) Code() int {
	return 200
}

func (o *ResearchTypesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ResearchTypes][%d] researchTypesCreateOK %s", 200, payload)
}

func (o *ResearchTypesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ResearchTypes][%d] researchTypesCreateOK %s", 200, payload)
}

func (o *ResearchTypesCreateOK) GetPayload() *models.ResearchType {
	return o.Payload
}

func (o *ResearchTypesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ResearchType)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewResearchTypesCreateDefault creates a ResearchTypesCreateDefault with default headers values
func NewResearchTypesCreateDefault(code int) *ResearchTypesCreateDefault {
	return &ResearchTypesCreateDefault{
		_statusCode: code,
	}
}

/*
ResearchTypesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ResearchTypesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this research types create default response has a 2xx status code
func (o *ResearchTypesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this research types create default response has a 3xx status code
func (o *ResearchTypesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this research types create default response has a 4xx status code
func (o *ResearchTypesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this research types create default response has a 5xx status code
func (o *ResearchTypesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this research types create default response a status code equal to that given
func (o *ResearchTypesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the research types create default response
func (o *ResearchTypesCreateDefault) Code() int {
	return o._statusCode
}

func (o *ResearchTypesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ResearchTypes][%d] ResearchTypes_Create default %s", o._statusCode, payload)
}

func (o *ResearchTypesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ResearchTypes][%d] ResearchTypes_Create default %s", o._statusCode, payload)
}

func (o *ResearchTypesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResearchTypesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
