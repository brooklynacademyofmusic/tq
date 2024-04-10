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

// OrderCategoriesCreateReader is a Reader for the OrderCategoriesCreate structure.
type OrderCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *OrderCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewOrderCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/OrderCategories] OrderCategories_Create", response, response.Code())
	}
}

// NewOrderCategoriesCreateOK creates a OrderCategoriesCreateOK with default headers values
func NewOrderCategoriesCreateOK() *OrderCategoriesCreateOK {
	return &OrderCategoriesCreateOK{}
}

/*
OrderCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type OrderCategoriesCreateOK struct {
	Payload *models.OrderCategory
}

// IsSuccess returns true when this order categories create o k response has a 2xx status code
func (o *OrderCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this order categories create o k response has a 3xx status code
func (o *OrderCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this order categories create o k response has a 4xx status code
func (o *OrderCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this order categories create o k response has a 5xx status code
func (o *OrderCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this order categories create o k response a status code equal to that given
func (o *OrderCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the order categories create o k response
func (o *OrderCategoriesCreateOK) Code() int {
	return 200
}

func (o *OrderCategoriesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/OrderCategories][%d] orderCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *OrderCategoriesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/OrderCategories][%d] orderCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *OrderCategoriesCreateOK) GetPayload() *models.OrderCategory {
	return o.Payload
}

func (o *OrderCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.OrderCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}