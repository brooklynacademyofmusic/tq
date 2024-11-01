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

// AssetTypesDeleteReader is a Reader for the AssetTypesDelete structure.
type AssetTypesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *AssetTypesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewAssetTypesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewAssetTypesDeleteDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewAssetTypesDeleteNoContent creates a AssetTypesDeleteNoContent with default headers values
func NewAssetTypesDeleteNoContent() *AssetTypesDeleteNoContent {
	return &AssetTypesDeleteNoContent{}
}

/*
AssetTypesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type AssetTypesDeleteNoContent struct {
}

// IsSuccess returns true when this asset types delete no content response has a 2xx status code
func (o *AssetTypesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this asset types delete no content response has a 3xx status code
func (o *AssetTypesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this asset types delete no content response has a 4xx status code
func (o *AssetTypesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this asset types delete no content response has a 5xx status code
func (o *AssetTypesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this asset types delete no content response a status code equal to that given
func (o *AssetTypesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the asset types delete no content response
func (o *AssetTypesDeleteNoContent) Code() int {
	return 204
}

func (o *AssetTypesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /ReferenceData/AssetTypes/{id}][%d] assetTypesDeleteNoContent", 204)
}

func (o *AssetTypesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /ReferenceData/AssetTypes/{id}][%d] assetTypesDeleteNoContent", 204)
}

func (o *AssetTypesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewAssetTypesDeleteDefault creates a AssetTypesDeleteDefault with default headers values
func NewAssetTypesDeleteDefault(code int) *AssetTypesDeleteDefault {
	return &AssetTypesDeleteDefault{
		_statusCode: code,
	}
}

/*
AssetTypesDeleteDefault describes a response with status code -1, with default header values.

Error
*/
type AssetTypesDeleteDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this asset types delete default response has a 2xx status code
func (o *AssetTypesDeleteDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this asset types delete default response has a 3xx status code
func (o *AssetTypesDeleteDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this asset types delete default response has a 4xx status code
func (o *AssetTypesDeleteDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this asset types delete default response has a 5xx status code
func (o *AssetTypesDeleteDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this asset types delete default response a status code equal to that given
func (o *AssetTypesDeleteDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the asset types delete default response
func (o *AssetTypesDeleteDefault) Code() int {
	return o._statusCode
}

func (o *AssetTypesDeleteDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/AssetTypes/{id}][%d] AssetTypes_Delete default %s", o._statusCode, payload)
}

func (o *AssetTypesDeleteDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[DELETE /ReferenceData/AssetTypes/{id}][%d] AssetTypes_Delete default %s", o._statusCode, payload)
}

func (o *AssetTypesDeleteDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *AssetTypesDeleteDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}