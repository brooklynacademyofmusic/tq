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

// RankingsCreateReader is a Reader for the RankingsCreate structure.
type RankingsCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RankingsCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRankingsCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewRankingsCreateDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewRankingsCreateOK creates a RankingsCreateOK with default headers values
func NewRankingsCreateOK() *RankingsCreateOK {
	return &RankingsCreateOK{}
}

/*
RankingsCreateOK describes a response with status code 200, with default header values.

OK
*/
type RankingsCreateOK struct {
	Payload *models.Ranking
}

// IsSuccess returns true when this rankings create o k response has a 2xx status code
func (o *RankingsCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this rankings create o k response has a 3xx status code
func (o *RankingsCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this rankings create o k response has a 4xx status code
func (o *RankingsCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this rankings create o k response has a 5xx status code
func (o *RankingsCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this rankings create o k response a status code equal to that given
func (o *RankingsCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the rankings create o k response
func (o *RankingsCreateOK) Code() int {
	return 200
}

func (o *RankingsCreateOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Rankings][%d] rankingsCreateOK %s", 200, payload)
}

func (o *RankingsCreateOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Rankings][%d] rankingsCreateOK %s", 200, payload)
}

func (o *RankingsCreateOK) GetPayload() *models.Ranking {
	return o.Payload
}

func (o *RankingsCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Ranking)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewRankingsCreateDefault creates a RankingsCreateDefault with default headers values
func NewRankingsCreateDefault(code int) *RankingsCreateDefault {
	return &RankingsCreateDefault{
		_statusCode: code,
	}
}

/*
RankingsCreateDefault describes a response with status code -1, with default header values.

Error
*/
type RankingsCreateDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this rankings create default response has a 2xx status code
func (o *RankingsCreateDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this rankings create default response has a 3xx status code
func (o *RankingsCreateDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this rankings create default response has a 4xx status code
func (o *RankingsCreateDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this rankings create default response has a 5xx status code
func (o *RankingsCreateDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this rankings create default response a status code equal to that given
func (o *RankingsCreateDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the rankings create default response
func (o *RankingsCreateDefault) Code() int {
	return o._statusCode
}

func (o *RankingsCreateDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Rankings][%d] Rankings_Create default %s", o._statusCode, payload)
}

func (o *RankingsCreateDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /CRM/Rankings][%d] Rankings_Create default %s", o._statusCode, payload)
}

func (o *RankingsCreateDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *RankingsCreateDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}