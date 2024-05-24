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

// GiftAidDocumentStatusesUpdateReader is a Reader for the GiftAidDocumentStatusesUpdate structure.
type GiftAidDocumentStatusesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GiftAidDocumentStatusesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGiftAidDocumentStatusesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGiftAidDocumentStatusesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGiftAidDocumentStatusesUpdateOK creates a GiftAidDocumentStatusesUpdateOK with default headers values
func NewGiftAidDocumentStatusesUpdateOK() *GiftAidDocumentStatusesUpdateOK {
	return &GiftAidDocumentStatusesUpdateOK{}
}

/*
GiftAidDocumentStatusesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type GiftAidDocumentStatusesUpdateOK struct {
	Payload *models.GiftAidDocumentStatus
}

// IsSuccess returns true when this gift aid document statuses update o k response has a 2xx status code
func (o *GiftAidDocumentStatusesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gift aid document statuses update o k response has a 3xx status code
func (o *GiftAidDocumentStatusesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gift aid document statuses update o k response has a 4xx status code
func (o *GiftAidDocumentStatusesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gift aid document statuses update o k response has a 5xx status code
func (o *GiftAidDocumentStatusesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gift aid document statuses update o k response a status code equal to that given
func (o *GiftAidDocumentStatusesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the gift aid document statuses update o k response
func (o *GiftAidDocumentStatusesUpdateOK) Code() int {
	return 200
}

func (o *GiftAidDocumentStatusesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidDocumentStatuses/{id}][%d] giftAidDocumentStatusesUpdateOK %s", 200, payload)
}

func (o *GiftAidDocumentStatusesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidDocumentStatuses/{id}][%d] giftAidDocumentStatusesUpdateOK %s", 200, payload)
}

func (o *GiftAidDocumentStatusesUpdateOK) GetPayload() *models.GiftAidDocumentStatus {
	return o.Payload
}

func (o *GiftAidDocumentStatusesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GiftAidDocumentStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGiftAidDocumentStatusesUpdateDefault creates a GiftAidDocumentStatusesUpdateDefault with default headers values
func NewGiftAidDocumentStatusesUpdateDefault(code int) *GiftAidDocumentStatusesUpdateDefault {
	return &GiftAidDocumentStatusesUpdateDefault{
		_statusCode: code,
	}
}

/*
GiftAidDocumentStatusesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type GiftAidDocumentStatusesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this gift aid document statuses update default response has a 2xx status code
func (o *GiftAidDocumentStatusesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this gift aid document statuses update default response has a 3xx status code
func (o *GiftAidDocumentStatusesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this gift aid document statuses update default response has a 4xx status code
func (o *GiftAidDocumentStatusesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this gift aid document statuses update default response has a 5xx status code
func (o *GiftAidDocumentStatusesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this gift aid document statuses update default response a status code equal to that given
func (o *GiftAidDocumentStatusesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the gift aid document statuses update default response
func (o *GiftAidDocumentStatusesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *GiftAidDocumentStatusesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidDocumentStatuses/{id}][%d] GiftAidDocumentStatuses_Update default %s", o._statusCode, payload)
}

func (o *GiftAidDocumentStatusesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidDocumentStatuses/{id}][%d] GiftAidDocumentStatuses_Update default %s", o._statusCode, payload)
}

func (o *GiftAidDocumentStatusesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GiftAidDocumentStatusesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
