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

// KeywordCategoriesCreateReader is a Reader for the KeywordCategoriesCreate structure.
type KeywordCategoriesCreateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *KeywordCategoriesCreateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewKeywordCategoriesCreateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /ReferenceData/KeywordCategories] KeywordCategories_Create", response, response.Code())
	}
}

// NewKeywordCategoriesCreateOK creates a KeywordCategoriesCreateOK with default headers values
func NewKeywordCategoriesCreateOK() *KeywordCategoriesCreateOK {
	return &KeywordCategoriesCreateOK{}
}

/*
KeywordCategoriesCreateOK describes a response with status code 200, with default header values.

OK
*/
type KeywordCategoriesCreateOK struct {
	Payload *models.KeywordCategory
}

// IsSuccess returns true when this keyword categories create o k response has a 2xx status code
func (o *KeywordCategoriesCreateOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this keyword categories create o k response has a 3xx status code
func (o *KeywordCategoriesCreateOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this keyword categories create o k response has a 4xx status code
func (o *KeywordCategoriesCreateOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this keyword categories create o k response has a 5xx status code
func (o *KeywordCategoriesCreateOK) IsServerError() bool {
	return false
}

// IsCode returns true when this keyword categories create o k response a status code equal to that given
func (o *KeywordCategoriesCreateOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the keyword categories create o k response
func (o *KeywordCategoriesCreateOK) Code() int {
	return 200
}

func (o *KeywordCategoriesCreateOK) Error() string {
	return fmt.Sprintf("[POST /ReferenceData/KeywordCategories][%d] keywordCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *KeywordCategoriesCreateOK) String() string {
	return fmt.Sprintf("[POST /ReferenceData/KeywordCategories][%d] keywordCategoriesCreateOK  %+v", 200, o.Payload)
}

func (o *KeywordCategoriesCreateOK) GetPayload() *models.KeywordCategory {
	return o.Payload
}

func (o *KeywordCategoriesCreateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.KeywordCategory)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}