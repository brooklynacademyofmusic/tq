// Code generated by go-swagger; DO NOT EDIT.

package g_e_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// MerchantReferencesReferenceReader is a Reader for the MerchantReferencesReference structure.
type MerchantReferencesReferenceReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *MerchantReferencesReferenceReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewMerchantReferencesReferenceOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /PaymentGateway/MerchantReference] MerchantReferences_Reference", response, response.Code())
	}
}

// NewMerchantReferencesReferenceOK creates a MerchantReferencesReferenceOK with default headers values
func NewMerchantReferencesReferenceOK() *MerchantReferencesReferenceOK {
	return &MerchantReferencesReferenceOK{}
}

/*
MerchantReferencesReferenceOK describes a response with status code 200, with default header values.

OK
*/
type MerchantReferencesReferenceOK struct {
	Payload *models.MerchantReference
}

// IsSuccess returns true when this merchant references reference o k response has a 2xx status code
func (o *MerchantReferencesReferenceOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this merchant references reference o k response has a 3xx status code
func (o *MerchantReferencesReferenceOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this merchant references reference o k response has a 4xx status code
func (o *MerchantReferencesReferenceOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this merchant references reference o k response has a 5xx status code
func (o *MerchantReferencesReferenceOK) IsServerError() bool {
	return false
}

// IsCode returns true when this merchant references reference o k response a status code equal to that given
func (o *MerchantReferencesReferenceOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the merchant references reference o k response
func (o *MerchantReferencesReferenceOK) Code() int {
	return 200
}

func (o *MerchantReferencesReferenceOK) Error() string {
	return fmt.Sprintf("[GET /PaymentGateway/MerchantReference][%d] merchantReferencesReferenceOK  %+v", 200, o.Payload)
}

func (o *MerchantReferencesReferenceOK) String() string {
	return fmt.Sprintf("[GET /PaymentGateway/MerchantReference][%d] merchantReferencesReferenceOK  %+v", 200, o.Payload)
}

func (o *MerchantReferencesReferenceOK) GetPayload() *models.MerchantReference {
	return o.Payload
}

func (o *MerchantReferencesReferenceOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.MerchantReference)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}