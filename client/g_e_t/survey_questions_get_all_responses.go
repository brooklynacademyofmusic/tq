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

// SurveyQuestionsGetAllReader is a Reader for the SurveyQuestionsGetAll structure.
type SurveyQuestionsGetAllReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SurveyQuestionsGetAllReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSurveyQuestionsGetAllOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewSurveyQuestionsGetAllDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewSurveyQuestionsGetAllOK creates a SurveyQuestionsGetAllOK with default headers values
func NewSurveyQuestionsGetAllOK() *SurveyQuestionsGetAllOK {
	return &SurveyQuestionsGetAllOK{}
}

/*
SurveyQuestionsGetAllOK describes a response with status code 200, with default header values.

OK
*/
type SurveyQuestionsGetAllOK struct {
	Payload []*models.SurveyQuestion
}

// IsSuccess returns true when this survey questions get all o k response has a 2xx status code
func (o *SurveyQuestionsGetAllOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this survey questions get all o k response has a 3xx status code
func (o *SurveyQuestionsGetAllOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this survey questions get all o k response has a 4xx status code
func (o *SurveyQuestionsGetAllOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this survey questions get all o k response has a 5xx status code
func (o *SurveyQuestionsGetAllOK) IsServerError() bool {
	return false
}

// IsCode returns true when this survey questions get all o k response a status code equal to that given
func (o *SurveyQuestionsGetAllOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the survey questions get all o k response
func (o *SurveyQuestionsGetAllOK) Code() int {
	return 200
}

func (o *SurveyQuestionsGetAllOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions][%d] surveyQuestionsGetAllOK %s", 200, payload)
}

func (o *SurveyQuestionsGetAllOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions][%d] surveyQuestionsGetAllOK %s", 200, payload)
}

func (o *SurveyQuestionsGetAllOK) GetPayload() []*models.SurveyQuestion {
	return o.Payload
}

func (o *SurveyQuestionsGetAllOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewSurveyQuestionsGetAllDefault creates a SurveyQuestionsGetAllDefault with default headers values
func NewSurveyQuestionsGetAllDefault(code int) *SurveyQuestionsGetAllDefault {
	return &SurveyQuestionsGetAllDefault{
		_statusCode: code,
	}
}

/*
SurveyQuestionsGetAllDefault describes a response with status code -1, with default header values.

Error
*/
type SurveyQuestionsGetAllDefault struct {
	_statusCode int

	Payload *models.ErrorMessage
}

// IsSuccess returns true when this survey questions get all default response has a 2xx status code
func (o *SurveyQuestionsGetAllDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this survey questions get all default response has a 3xx status code
func (o *SurveyQuestionsGetAllDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this survey questions get all default response has a 4xx status code
func (o *SurveyQuestionsGetAllDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this survey questions get all default response has a 5xx status code
func (o *SurveyQuestionsGetAllDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this survey questions get all default response a status code equal to that given
func (o *SurveyQuestionsGetAllDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the survey questions get all default response
func (o *SurveyQuestionsGetAllDefault) Code() int {
	return o._statusCode
}

func (o *SurveyQuestionsGetAllDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions][%d] SurveyQuestions_GetAll default %s", o._statusCode, payload)
}

func (o *SurveyQuestionsGetAllDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /ReferenceData/SurveyQuestions][%d] SurveyQuestions_GetAll default %s", o._statusCode, payload)
}

func (o *SurveyQuestionsGetAllDefault) GetPayload() *models.ErrorMessage {
	return o.Payload
}

func (o *SurveyQuestionsGetAllDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ErrorMessage)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
