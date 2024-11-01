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

// ResearchDeleteReader is a Reader for the ResearchDelete structure.
type ResearchDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResearchDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewResearchDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResearchDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResearchDeleteNoContent creates a ResearchDeleteNoContent with default headers values
func NewResearchDeleteNoContent() *ResearchDeleteNoContent {
	return &ResearchDeleteNoContent{}
}

/*
ResearchDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ResearchDeleteNoContent struct {
}

// IsSuccess returns true when this research delete no content response has a 2xx status code
func (o *ResearchDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this research delete no content response has a 3xx status code
func (o *ResearchDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this research delete no content response has a 4xx status code
func (o *ResearchDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this research delete no content response has a 5xx status code
func (o *ResearchDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this research delete no content response a status code equal to that given
func (o *ResearchDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the research delete no content response
func (o *ResearchDeleteNoContent) Code() int {
	return 204
}

func (o *ResearchDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /CRM/Research/{researchEntryId}][%d] researchDeleteNoContent", 204)
}

func (o *ResearchDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /CRM/Research/{researchEntryId}][%d] researchDeleteNoContent", 204)
}

func (o *ResearchDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewResearchDeleteDefault creates a ResearchDeleteDefault with default headers values
func NewResearchDeleteDefault(code int) *ResearchDeleteDefault {
	return &ResearchDeleteDefault{
		_statusCode: code,
	}
}

/*
ResearchDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ResearchDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this research delete default response has a 2xx status code
func (o *ResearchDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this research delete default response has a 3xx status code
func (o *ResearchDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this research delete default response has a 4xx status code
func (o *ResearchDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this research delete default response has a 5xx status code
func (o *ResearchDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this research delete default response a status code equal to that given
func (o *ResearchDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the research delete default response
func (o *ResearchDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ResearchDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /CRM/Research/{researchEntryId}][%d] Research_Delete default %s", o._statusCode, payload)
}

func (o *ResearchDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /CRM/Research/{researchEntryId}][%d] Research_Delete default %s", o._statusCode, payload)
}

func (o *ResearchDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ResearchDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}