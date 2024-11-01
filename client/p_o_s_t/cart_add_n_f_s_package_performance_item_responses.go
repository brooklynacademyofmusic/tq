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

// CartAddNFSPackagePerformanceItemReader is a Reader for the CartAddNFSPackagePerformanceItem structure.
type CartAddNFSPackagePerformanceItemReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CartAddNFSPackagePerformanceItemReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCartAddNFSPackagePerformanceItemOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewCartAddNFSPackagePerformanceItemDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewCartAddNFSPackagePerformanceItemOK creates a CartAddNFSPackagePerformanceItemOK with default headers values
func NewCartAddNFSPackagePerformanceItemOK() *CartAddNFSPackagePerformanceItemOK {
	return &CartAddNFSPackagePerformanceItemOK{}
}

/*
CartAddNFSPackagePerformanceItemOK describes a response with status code 200, with default header values.

OK
*/
type CartAddNFSPackagePerformanceItemOK struct {
	Payload *models.AddNFSPackagePerformanceItemResponse
}

// IsSuccess returns true when this cart add n f s package performance item o k response has a 2xx status code
func (o *CartAddNFSPackagePerformanceItemOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this cart add n f s package performance item o k response has a 3xx status code
func (o *CartAddNFSPackagePerformanceItemOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this cart add n f s package performance item o k response has a 4xx status code
func (o *CartAddNFSPackagePerformanceItemOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this cart add n f s package performance item o k response has a 5xx status code
func (o *CartAddNFSPackagePerformanceItemOK) IsServerError() bool {
	return false
}

// IsCode returns true when this cart add n f s package performance item o k response a status code equal to that given
func (o *CartAddNFSPackagePerformanceItemOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the cart add n f s package performance item o k response
func (o *CartAddNFSPackagePerformanceItemOK) Code() int {
	return 200
}

func (o *CartAddNFSPackagePerformanceItemOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Packages/Nfs][%d] cartAddNFSPackagePerformanceItemOK %s", 200, payload)
}

func (o *CartAddNFSPackagePerformanceItemOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Packages/Nfs][%d] cartAddNFSPackagePerformanceItemOK %s", 200, payload)
}

func (o *CartAddNFSPackagePerformanceItemOK) GetPayload() *models.AddNFSPackagePerformanceItemResponse {
	return o.Payload
}

func (o *CartAddNFSPackagePerformanceItemOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.AddNFSPackagePerformanceItemResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewCartAddNFSPackagePerformanceItemDefault creates a CartAddNFSPackagePerformanceItemDefault with default headers values
func NewCartAddNFSPackagePerformanceItemDefault(code int) *CartAddNFSPackagePerformanceItemDefault {
	return &CartAddNFSPackagePerformanceItemDefault{
		_statusCode: code,
	}
}

/*
CartAddNFSPackagePerformanceItemDefault describes a response with status code -1, with default header values.

Error
*/
type CartAddNFSPackagePerformanceItemDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this cart add n f s package performance item default response has a 2xx status code
func (o *CartAddNFSPackagePerformanceItemDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this cart add n f s package performance item default response has a 3xx status code
func (o *CartAddNFSPackagePerformanceItemDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this cart add n f s package performance item default response has a 4xx status code
func (o *CartAddNFSPackagePerformanceItemDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this cart add n f s package performance item default response has a 5xx status code
func (o *CartAddNFSPackagePerformanceItemDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this cart add n f s package performance item default response a status code equal to that given
func (o *CartAddNFSPackagePerformanceItemDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the cart add n f s package performance item default response
func (o *CartAddNFSPackagePerformanceItemDefault) Code() int {
	return o._statusCode
}

func (o *CartAddNFSPackagePerformanceItemDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Packages/Nfs][%d] Cart_AddNFSPackagePerformanceItem default %s", o._statusCode, payload)
}

func (o *CartAddNFSPackagePerformanceItemDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /Web/Cart/{sessionKey}/Packages/Nfs][%d] Cart_AddNFSPackagePerformanceItem default %s", o._statusCode, payload)
}

func (o *CartAddNFSPackagePerformanceItemDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *CartAddNFSPackagePerformanceItemDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}