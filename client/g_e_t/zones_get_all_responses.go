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

// ZonesGetAllReader is a Reader for the ZonesGetAll structure.
type ZonesGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ZonesGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewZonesGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewZonesGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewZonesGetAllOK creates a ZonesGetAllOK with default headers values
func NewZonesGetAllOK() *ZonesGetAllOK {
	return &ZonesGetAllOK{}
}

/*
ZonesGetAllOK describes a response with status code 200, with default header values.

OK
*/
type ZonesGetAllOK struct {
	Payload []*models.Zone
}

// IsSuccess returns true when this zones get all o k response has a 2xx status code
func (o *ZonesGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this zones get all o k response has a 3xx status code
func (o *ZonesGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this zones get all o k response has a 4xx status code
func (o *ZonesGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this zones get all o k response has a 5xx status code
func (o *ZonesGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this zones get all o k response a status code equal to that given
func (o *ZonesGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the zones get all o k response
func (o *ZonesGetAllOK) Code() int {
	return 200
}

func (o *ZonesGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones][%d] zonesGetAllOK %s", 200, payload)
}

func (o *ZonesGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones][%d] zonesGetAllOK %s", 200, payload)
}

func (o *ZonesGetAllOK) GetPayload() []*models.Zone {
	return o.Payload
}

func (o *ZonesGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewZonesGetAllDefault creates a ZonesGetAllDefault with default headers values
func NewZonesGetAllDefault(code int) *ZonesGetAllDefault {
	return &ZonesGetAllDefault{
		_statusCode: code,
	}
}

/*
ZonesGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type ZonesGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this zones get all default response has a 2xx status code
func (o *ZonesGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this zones get all default response has a 3xx status code
func (o *ZonesGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this zones get all default response has a 4xx status code
func (o *ZonesGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this zones get all default response has a 5xx status code
func (o *ZonesGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this zones get all default response a status code equal to that given
func (o *ZonesGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the zones get all default response
func (o *ZonesGetAllDefault) Code() int {
	return o._statusCode
}

func (o *ZonesGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones][%d] Zones_GetAll default %s", o._statusCode, payload)
}

func (o *ZonesGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /TXN/Zones][%d] Zones_GetAll default %s", o._statusCode, payload)
}

func (o *ZonesGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *ZonesGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
