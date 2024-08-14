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

// PackageWebContentsDeleteReader is a Reader for the PackageWebContentsDelete structure.
type PackageWebContentsDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PackageWebContentsDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPackageWebContentsDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPackageWebContentsDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPackageWebContentsDeleteNoContent creates a PackageWebContentsDeleteNoContent with default headers values
func NewPackageWebContentsDeleteNoContent() *PackageWebContentsDeleteNoContent {
	return &PackageWebContentsDeleteNoContent{}
}

/*
PackageWebContentsDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PackageWebContentsDeleteNoContent struct {
}

// IsSuccess returns true when this package web contents delete no content response has a 2xx status code
func (o *PackageWebContentsDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this package web contents delete no content response has a 3xx status code
func (o *PackageWebContentsDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this package web contents delete no content response has a 4xx status code
func (o *PackageWebContentsDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this package web contents delete no content response has a 5xx status code
func (o *PackageWebContentsDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this package web contents delete no content response a status code equal to that given
func (o *PackageWebContentsDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the package web contents delete no content response
func (o *PackageWebContentsDeleteNoContent) Code() int {
	return 204
}

func (o *PackageWebContentsDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /Txn/PackageWebContents/{packageWebContentId}][%d] packageWebContentsDeleteNoContent", 204)
}

func (o *PackageWebContentsDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /Txn/PackageWebContents/{packageWebContentId}][%d] packageWebContentsDeleteNoContent", 204)
}

func (o *PackageWebContentsDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewPackageWebContentsDeleteDefault creates a PackageWebContentsDeleteDefault with default headers values
func NewPackageWebContentsDeleteDefault(code int) *PackageWebContentsDeleteDefault {
	return &PackageWebContentsDeleteDefault{
		_statusCode: code,
	}
}

/*
PackageWebContentsDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type PackageWebContentsDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this package web contents delete default response has a 2xx status code
func (o *PackageWebContentsDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this package web contents delete default response has a 3xx status code
func (o *PackageWebContentsDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this package web contents delete default response has a 4xx status code
func (o *PackageWebContentsDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this package web contents delete default response has a 5xx status code
func (o *PackageWebContentsDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this package web contents delete default response a status code equal to that given
func (o *PackageWebContentsDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the package web contents delete default response
func (o *PackageWebContentsDeleteDefault) Code() int {
	return o._statusCode
}

func (o *PackageWebContentsDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Txn/PackageWebContents/{packageWebContentId}][%d] PackageWebContents_Delete default %s", o._statusCode, payload)
}

func (o *PackageWebContentsDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /Txn/PackageWebContents/{packageWebContentId}][%d] PackageWebContents_Delete default %s", o._statusCode, payload)
}

func (o *PackageWebContentsDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *PackageWebContentsDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}