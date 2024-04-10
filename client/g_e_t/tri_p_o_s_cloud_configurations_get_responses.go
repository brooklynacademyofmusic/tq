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

// TriPOSCloudConfigurationsGetReader is a Reader for the TriPOSCloudConfigurationsGet structure.
type TriPOSCloudConfigurationsGetReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *TriPOSCloudConfigurationsGetReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewTriPOSCloudConfigurationsGetOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[GET /ReferenceData/TriPOSCloudConfigurations/{id}] TriPOSCloudConfigurations_Get", response, response.Code())
	}
}

// NewTriPOSCloudConfigurationsGetOK creates a TriPOSCloudConfigurationsGetOK with default headers values
func NewTriPOSCloudConfigurationsGetOK() *TriPOSCloudConfigurationsGetOK {
	return &TriPOSCloudConfigurationsGetOK{}
}

/*
TriPOSCloudConfigurationsGetOK describes a response with status code 200, with default header values.

OK
*/
type TriPOSCloudConfigurationsGetOK struct {
	Payload *models.TriPOSCloudConfiguration
}

// IsSuccess returns true when this tri p o s cloud configurations get o k response has a 2xx status code
func (o *TriPOSCloudConfigurationsGetOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this tri p o s cloud configurations get o k response has a 3xx status code
func (o *TriPOSCloudConfigurationsGetOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this tri p o s cloud configurations get o k response has a 4xx status code
func (o *TriPOSCloudConfigurationsGetOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this tri p o s cloud configurations get o k response has a 5xx status code
func (o *TriPOSCloudConfigurationsGetOK) IsServerError() bool {
	return false
}

// IsCode returns true when this tri p o s cloud configurations get o k response a status code equal to that given
func (o *TriPOSCloudConfigurationsGetOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the tri p o s cloud configurations get o k response
func (o *TriPOSCloudConfigurationsGetOK) Code() int {
	return 200
}

func (o *TriPOSCloudConfigurationsGetOK) Error() string {
	return fmt.Sprintf("[GET /ReferenceData/TriPOSCloudConfigurations/{id}][%d] triPOSCloudConfigurationsGetOK  %+v", 200, o.Payload)
}

func (o *TriPOSCloudConfigurationsGetOK) String() string {
	return fmt.Sprintf("[GET /ReferenceData/TriPOSCloudConfigurations/{id}][%d] triPOSCloudConfigurationsGetOK  %+v", 200, o.Payload)
}

func (o *TriPOSCloudConfigurationsGetOK) GetPayload() *models.TriPOSCloudConfiguration {
	return o.Payload
}

func (o *TriPOSCloudConfigurationsGetOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.TriPOSCloudConfiguration)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}