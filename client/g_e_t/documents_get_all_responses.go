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

// DocumentsGetAllReader is a Reader for the DocumentsGetAll structure.
type DocumentsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DocumentsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDocumentsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewDocumentsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewDocumentsGetAllOK creates a DocumentsGetAllOK with default headers values
func NewDocumentsGetAllOK() *DocumentsGetAllOK {
	return &DocumentsGetAllOK{}
}

/*
DocumentsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type DocumentsGetAllOK struct {
	Payload []*models.Document
}

// IsSuccess returns true when this documents get all o k response has a 2xx status code
func (o *DocumentsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this documents get all o k response has a 3xx status code
func (o *DocumentsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this documents get all o k response has a 4xx status code
func (o *DocumentsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this documents get all o k response has a 5xx status code
func (o *DocumentsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this documents get all o k response a status code equal to that given
func (o *DocumentsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the documents get all o k response
func (o *DocumentsGetAllOK) Code() int {
	return 200
}

func (o *DocumentsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Documents][%d] documentsGetAllOK %s", 200, payload)
}

func (o *DocumentsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Documents][%d] documentsGetAllOK %s", 200, payload)
}

func (o *DocumentsGetAllOK) GetPayload() []*models.Document {
	return o.Payload
}

func (o *DocumentsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDocumentsGetAllDefault creates a DocumentsGetAllDefault with default headers values
func NewDocumentsGetAllDefault(code int) *DocumentsGetAllDefault {
	return &DocumentsGetAllDefault{
		_statusCode: code,
	}
}

/*
DocumentsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type DocumentsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this documents get all default response has a 2xx status code
func (o *DocumentsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this documents get all default response has a 3xx status code
func (o *DocumentsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this documents get all default response has a 4xx status code
func (o *DocumentsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this documents get all default response has a 5xx status code
func (o *DocumentsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this documents get all default response a status code equal to that given
func (o *DocumentsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the documents get all default response
func (o *DocumentsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *DocumentsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Documents][%d] Documents_GetAll default %s", o._statusCode, payload)
}

func (o *DocumentsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /Finance/Documents][%d] Documents_GetAll default %s", o._statusCode, payload)
}

func (o *DocumentsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *DocumentsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
