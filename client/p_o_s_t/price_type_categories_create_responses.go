// Code generated by go-swagger; DO NOT EDIT.

package p_o_s_t

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/skysyzygy/tq/models"
)

// PriceTypeCategoriesCreateReader is a Reader for the PriceTypeCategoriesCreate structure.
type PriceTypeCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PriceTypeCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPriceTypeCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/PriceTypeCategories] PriceTypeCategories_Create", response, response.Code())
	}
}

// NewPriceTypeCategoriesCreateOK creates a PriceTypeCategoriesCreateOK with default headers values
func NewPriceTypeCategoriesCreateOK() *PriceTypeCategoriesCreateOK {
	return &PriceTypeCategoriesCreateOK{}
}

/*
PriceTypeCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type PriceTypeCategoriesCreateOK struct {
	Payload *models.PriceTypeCategory
}

// IsSuccess returns true when this price type categories create o k response has a 2xx status code
func (o *PriceTypeCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this price type categories create o k response has a 3xx status code
func (o *PriceTypeCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this price type categories create o k response has a 4xx status code
func (o *PriceTypeCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this price type categories create o k response has a 5xx status code
func (o *PriceTypeCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this price type categories create o k response a status code equal to that given
func (o *PriceTypeCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the price type categories create o k response
func (o *PriceTypeCategoriesCreateOK) Code() int {
	return 200
}

func (o *PriceTypeCategoriesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/PriceTypeCategories][%d] priceTypeCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *PriceTypeCategoriesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/PriceTypeCategories][%d] priceTypeCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *PriceTypeCategoriesCreateOK) GetPayload() *models.PriceTypeCategory {
	return o.Payload
}

func (o *PriceTypeCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.PriceTypeCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}