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

// ActivityCategoriesCreateReader is a Reader for the ActivityCategoriesCreate structure.
type ActivityCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ActivityCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewActivityCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewActivityCategoriesCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewActivityCategoriesCreateOK creates a ActivityCategoriesCreateOK with default headers values
func NewActivityCategoriesCreateOK() *ActivityCategoriesCreateOK {
	return &ActivityCategoriesCreateOK{}
}

/*
ActivityCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type ActivityCategoriesCreateOK struct {
	Payload *models.ActivityCategory
}

// IsSuccess returns true when this activity categories create o k response has a 2xx status code
func (o *ActivityCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this activity categories create o k response has a 3xx status code
func (o *ActivityCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this activity categories create o k response has a 4xx status code
func (o *ActivityCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this activity categories create o k response has a 5xx status code
func (o *ActivityCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this activity categories create o k response a status code equal to that given
func (o *ActivityCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the activity categories create o k response
func (o *ActivityCategoriesCreateOK) Code() int {
	return 200
}

func (o *ActivityCategoriesCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ActivityCategories][%d] activityCategoriesCreateOK %s", 200, payload)
}

func (o *ActivityCategoriesCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ActivityCategories][%d] activityCategoriesCreateOK %s", 200, payload)
}

func (o *ActivityCategoriesCreateOK) GetPayload() *models.ActivityCategory {
	return o.Payload
}

func (o *ActivityCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewActivityCategoriesCreateDefault creates a ActivityCategoriesCreateDefault with default headers values
func NewActivityCategoriesCreateDefault(code int) *ActivityCategoriesCreateDefault {
	return &ActivityCategoriesCreateDefault{
		_statusCode: code,
	}
}

/*
ActivityCategoriesCreateDefault describes a response with status code -1, with default header values.

Error
*/
type ActivityCategoriesCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this activity categories create default response has a 2xx status code
func (o *ActivityCategoriesCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this activity categories create default response has a 3xx status code
func (o *ActivityCategoriesCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this activity categories create default response has a 4xx status code
func (o *ActivityCategoriesCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this activity categories create default response has a 5xx status code
func (o *ActivityCategoriesCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this activity categories create default response a status code equal to that given
func (o *ActivityCategoriesCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the activity categories create default response
func (o *ActivityCategoriesCreateDefault) Code() int {
	return o._statusCode
}

func (o *ActivityCategoriesCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ActivityCategories][%d] ActivityCategories_Create default %s", o._statusCode, payload)
}

func (o *ActivityCategoriesCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /ReferenceData/ActivityCategories][%d] ActivityCategories_Create default %s", o._statusCode, payload)
}

func (o *ActivityCategoriesCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ActivityCategoriesCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}