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

// QualificationCategoriesCreateReader is a Reader for the QualificationCategoriesCreate structure.
type QualificationCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *QualificationCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewQualificationCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewQualificationCategoriesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewQualificationCategoriesCreateOK creates a QualificationCategoriesCreateOK with default headers values
func NewQualificationCategoriesCreateOK() *QualificationCategoriesCreateOK {
	return &QualificationCategoriesCreateOK{}
}

/*
QualificationCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type QualificationCategoriesCreateOK struct {
	Payload *models.QualificationCategory
}

// IsSuccess returns true when this qualification categories create o k response has a 2xx status code
func (o *QualificationCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this qualification categories create o k response has a 3xx status code
func (o *QualificationCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this qualification categories create o k response has a 4xx status code
func (o *QualificationCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this qualification categories create o k response has a 5xx status code
func (o *QualificationCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this qualification categories create o k response a status code equal to that given
func (o *QualificationCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the qualification categories create o k response
func (o *QualificationCategoriesCreateOK) Code() int {
	return 200
}

func (o *QualificationCategoriesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/QualificationCategories][%d] qualificationCategoriesCreateOK %s", 200, payload)
}

func (o *QualificationCategoriesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/QualificationCategories][%d] qualificationCategoriesCreateOK %s", 200, payload)
}

func (o *QualificationCategoriesCreateOK) GetPayload() *models.QualificationCategory {
	return o.Payload
}

func (o *QualificationCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.QualificationCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewQualificationCategoriesCreateDefault creates a QualificationCategoriesCreateDefault with default headers values
func NewQualificationCategoriesCreateDefault(code int) *QualificationCategoriesCreateDefault {
	return &QualificationCategoriesCreateDefault{
		_statusCode: code,
	}
}

/*
QualificationCategoriesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type QualificationCategoriesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this qualification categories create default response has a 2xx status code
func (o *QualificationCategoriesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this qualification categories create default response has a 3xx status code
func (o *QualificationCategoriesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this qualification categories create default response has a 4xx status code
func (o *QualificationCategoriesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this qualification categories create default response has a 5xx status code
func (o *QualificationCategoriesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this qualification categories create default response a status code equal to that given
func (o *QualificationCategoriesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the qualification categories create default response
func (o *QualificationCategoriesCreateDefault) Code() int {
	return o._statusCode
}

func (o *QualificationCategoriesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/QualificationCategories][%d] QualificationCategories_Create default %s", o._statusCode, payload)
}

func (o *QualificationCategoriesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/QualificationCategories][%d] QualificationCategories_Create default %s", o._statusCode, payload)
}

func (o *QualificationCategoriesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *QualificationCategoriesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}