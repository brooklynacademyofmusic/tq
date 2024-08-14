// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

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

// CustomDefaultsDeleteReader is a Reader for the CustomDefaultsDelete structure.
type CustomDefaultsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CustomDefaultsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewCustomDefaultsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCustomDefaultsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCustomDefaultsDeleteNoContent creates a CustomDefaultsDeleteNoContent with default headers values
func NewCustomDefaultsDeleteNoContent() *CustomDefaultsDeleteNoContent {
	return &CustomDefaultsDeleteNoContent{}
}

/*
CustomDefaultsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type CustomDefaultsDeleteNoContent struct {
}

// IsSuccess returns true when this custom defaults delete no content response has a 2xx status code
func (o *CustomDefaultsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this custom defaults delete no content response has a 3xx status code
func (o *CustomDefaultsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this custom defaults delete no content response has a 4xx status code
func (o *CustomDefaultsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this custom defaults delete no content response has a 5xx status code
func (o *CustomDefaultsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this custom defaults delete no content response a status code equal to that given
func (o *CustomDefaultsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the custom defaults delete no content response
func (o *CustomDefaultsDeleteNoContent) Code() int {
	return 204
}

func (o *CustomDefaultsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/CustomDefaults/{id}][%d] customDefaultsDeleteNoContent", 204)
}

func (o *CustomDefaultsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/CustomDefaults/{id}][%d] customDefaultsDeleteNoContent", 204)
}

func (o *CustomDefaultsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewCustomDefaultsDeleteDefault creates a CustomDefaultsDeleteDefault with default headers values
func NewCustomDefaultsDeleteDefault(code int) *CustomDefaultsDeleteDefault {
	return &CustomDefaultsDeleteDefault{
		_statusCode: code,
	}
}

/*
CustomDefaultsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type CustomDefaultsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this custom defaults delete default response has a 2xx status code
func (o *CustomDefaultsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this custom defaults delete default response has a 3xx status code
func (o *CustomDefaultsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this custom defaults delete default response has a 4xx status code
func (o *CustomDefaultsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this custom defaults delete default response has a 5xx status code
func (o *CustomDefaultsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this custom defaults delete default response a status code equal to that given
func (o *CustomDefaultsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the custom defaults delete default response
func (o *CustomDefaultsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *CustomDefaultsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/CustomDefaults/{id}][%d] CustomDefaults_Delete default %s", o._statusCode, payload)
}

func (o *CustomDefaultsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/CustomDefaults/{id}][%d] CustomDefaults_Delete default %s", o._statusCode, payload)
}

func (o *CustomDefaultsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CustomDefaultsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}