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

// ZoneMapsDeleteReader is a Reader for the ZoneMapsDelete structure.
type ZoneMapsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ZoneMapsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewZoneMapsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewZoneMapsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewZoneMapsDeleteNoContent creates a ZoneMapsDeleteNoContent with default headers values
func NewZoneMapsDeleteNoContent() *ZoneMapsDeleteNoContent {
	return &ZoneMapsDeleteNoContent{}
}

/*
ZoneMapsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type ZoneMapsDeleteNoContent struct {
}

// IsSuccess returns true when this zone maps delete no content response has a 2xx status code
func (o *ZoneMapsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this zone maps delete no content response has a 3xx status code
func (o *ZoneMapsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this zone maps delete no content response has a 4xx status code
func (o *ZoneMapsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this zone maps delete no content response has a 5xx status code
func (o *ZoneMapsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this zone maps delete no content response a status code equal to that given
func (o *ZoneMapsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the zone maps delete no content response
func (o *ZoneMapsDeleteNoContent) Code() int {
	return 204
}

func (o *ZoneMapsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/ZoneMaps/{id}][%d] zoneMapsDeleteNoContent", 204)
}

func (o *ZoneMapsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/ZoneMaps/{id}][%d] zoneMapsDeleteNoContent", 204)
}

func (o *ZoneMapsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewZoneMapsDeleteDefault creates a ZoneMapsDeleteDefault with default headers values
func NewZoneMapsDeleteDefault(code int) *ZoneMapsDeleteDefault {
	return &ZoneMapsDeleteDefault{
		_statusCode: code,
	}
}

/*
ZoneMapsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type ZoneMapsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this zone maps delete default response has a 2xx status code
func (o *ZoneMapsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this zone maps delete default response has a 3xx status code
func (o *ZoneMapsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this zone maps delete default response has a 4xx status code
func (o *ZoneMapsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this zone maps delete default response has a 5xx status code
func (o *ZoneMapsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this zone maps delete default response a status code equal to that given
func (o *ZoneMapsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the zone maps delete default response
func (o *ZoneMapsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *ZoneMapsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/ZoneMaps/{id}][%d] ZoneMaps_Delete default %s", o._statusCode, payload)
}

func (o *ZoneMapsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /TXN/ZoneMaps/{id}][%d] ZoneMaps_Delete default %s", o._statusCode, payload)
}

func (o *ZoneMapsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ZoneMapsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}