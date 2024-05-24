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

// GiftAidStatusesUpdateReader is a Reader for the GiftAidStatusesUpdate structure.
type GiftAidStatusesUpdateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GiftAidStatusesUpdateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGiftAidStatusesUpdateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGiftAidStatusesUpdateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGiftAidStatusesUpdateOK creates a GiftAidStatusesUpdateOK with default headers values
func NewGiftAidStatusesUpdateOK() *GiftAidStatusesUpdateOK {
	return &GiftAidStatusesUpdateOK{}
}

/*
GiftAidStatusesUpdateOK describes a response with status code 200, with default header values.

OK
*/
type GiftAidStatusesUpdateOK struct {
	Payload *models.GiftAidStatus
}

// IsSuccess returns true when this gift aid statuses update o k response has a 2xx status code
func (o *GiftAidStatusesUpdateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this gift aid statuses update o k response has a 3xx status code
func (o *GiftAidStatusesUpdateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this gift aid statuses update o k response has a 4xx status code
func (o *GiftAidStatusesUpdateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this gift aid statuses update o k response has a 5xx status code
func (o *GiftAidStatusesUpdateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this gift aid statuses update o k response a status code equal to that given
func (o *GiftAidStatusesUpdateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the gift aid statuses update o k response
func (o *GiftAidStatusesUpdateOK) Code() int {
	return 200
}

func (o *GiftAidStatusesUpdateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidStatuses/{id}][%d] giftAidStatusesUpdateOK %s", 200, payload)
}

func (o *GiftAidStatusesUpdateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidStatuses/{id}][%d] giftAidStatusesUpdateOK %s", 200, payload)
}

func (o *GiftAidStatusesUpdateOK) GetPayload() *models.GiftAidStatus {
	return o.Payload
}

func (o *GiftAidStatusesUpdateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.GiftAidStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGiftAidStatusesUpdateDefault creates a GiftAidStatusesUpdateDefault with default headers values
func NewGiftAidStatusesUpdateDefault(code int) *GiftAidStatusesUpdateDefault {
	return &GiftAidStatusesUpdateDefault{
		_statusCode: code,
	}
}

/*
GiftAidStatusesUpdateDefault describes a response with status code -1, with default header values.

Error
*/
type GiftAidStatusesUpdateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this gift aid statuses update default response has a 2xx status code
func (o *GiftAidStatusesUpdateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this gift aid statuses update default response has a 3xx status code
func (o *GiftAidStatusesUpdateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this gift aid statuses update default response has a 4xx status code
func (o *GiftAidStatusesUpdateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this gift aid statuses update default response has a 5xx status code
func (o *GiftAidStatusesUpdateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this gift aid statuses update default response a status code equal to that given
func (o *GiftAidStatusesUpdateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the gift aid statuses update default response
func (o *GiftAidStatusesUpdateDefault) Code() int {
	return o._statusCode
}

func (o *GiftAidStatusesUpdateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidStatuses/{id}][%d] GiftAidStatuses_Update default %s", o._statusCode, payload)
}

func (o *GiftAidStatusesUpdateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[PUT /ReferenceData/GiftAidStatuses/{id}][%d] GiftAidStatuses_Update default %s", o._statusCode, payload)
}

func (o *GiftAidStatusesUpdateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *GiftAidStatusesUpdateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
