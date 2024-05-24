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

// AffiliationsDeleteReader is a Reader for the AffiliationsDelete structure.
type AffiliationsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AffiliationsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewAffiliationsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAffiliationsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAffiliationsDeleteNoContent creates a AffiliationsDeleteNoContent with default headers values
func NewAffiliationsDeleteNoContent() *AffiliationsDeleteNoContent {
	return &AffiliationsDeleteNoContent{}
}

/*
AffiliationsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type AffiliationsDeleteNoContent struct {
}

// IsSuccess returns true when this affiliations delete no content response has a 2xx status code
func (o *AffiliationsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this affiliations delete no content response has a 3xx status code
func (o *AffiliationsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this affiliations delete no content response has a 4xx status code
func (o *AffiliationsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this affiliations delete no content response has a 5xx status code
func (o *AffiliationsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this affiliations delete no content response a status code equal to that given
func (o *AffiliationsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the affiliations delete no content response
func (o *AffiliationsDeleteNoContent) Code() int {
	return 204
}

func (o *AffiliationsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /CRM/Affiliations/{affiliationId}][%d] affiliationsDeleteNoContent", 204)
}

func (o *AffiliationsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /CRM/Affiliations/{affiliationId}][%d] affiliationsDeleteNoContent", 204)
}

func (o *AffiliationsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAffiliationsDeleteDefault creates a AffiliationsDeleteDefault with default headers values
func NewAffiliationsDeleteDefault(code int) *AffiliationsDeleteDefault {
	return &AffiliationsDeleteDefault{
		_statusCode: code,
	}
}

/*
AffiliationsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type AffiliationsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this affiliations delete default response has a 2xx status code
func (o *AffiliationsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this affiliations delete default response has a 3xx status code
func (o *AffiliationsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this affiliations delete default response has a 4xx status code
func (o *AffiliationsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this affiliations delete default response has a 5xx status code
func (o *AffiliationsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this affiliations delete default response a status code equal to that given
func (o *AffiliationsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the affiliations delete default response
func (o *AffiliationsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *AffiliationsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /CRM/Affiliations/{affiliationId}][%d] Affiliations_Delete default %s", o._statusCode, payload)
}

func (o *AffiliationsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /CRM/Affiliations/{affiliationId}][%d] Affiliations_Delete default %s", o._statusCode, payload)
}

func (o *AffiliationsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AffiliationsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
