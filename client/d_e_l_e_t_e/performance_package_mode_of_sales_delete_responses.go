// Code generated by go-swagger; DO NOT EDIT.

package d_e_l_e_t_e

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// PerformancePackageModeOfSalesDeleteReader is a Reader for the PerformancePackageModeOfSalesDelete structure.
type PerformancePackageModeOfSalesDeleteReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PerformancePackageModeOfSalesDeleteReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 204:
		result := NewPerformancePackageModeOfSalesDeleteNoContent()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[DELETE /TXN/PerformancePackageModeOfSales/{performancePackageModeOfSaleId}] PerformancePackageModeOfSales_Delete", response, response.Code())
	}
}

// NewPerformancePackageModeOfSalesDeleteNoContent creates a PerformancePackageModeOfSalesDeleteNoContent with default headers values
func NewPerformancePackageModeOfSalesDeleteNoContent() *PerformancePackageModeOfSalesDeleteNoContent {
	return &PerformancePackageModeOfSalesDeleteNoContent{}
}

/*
PerformancePackageModeOfSalesDeleteNoContent describes a response with status code 204, with default header values.

No Content
*/
type PerformancePackageModeOfSalesDeleteNoContent struct {
}

// IsSuccess returns true when this performance package mode of sales delete no content response has a 2xx status code
func (o *PerformancePackageModeOfSalesDeleteNoContent) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this performance package mode of sales delete no content response has a 3xx status code
func (o *PerformancePackageModeOfSalesDeleteNoContent) IsRedirect() bool {
	return false
}

// IsClientError returns true when this performance package mode of sales delete no content response has a 4xx status code
func (o *PerformancePackageModeOfSalesDeleteNoContent) IsClientError() bool {
	return false
}

// IsServerError returns true when this performance package mode of sales delete no content response has a 5xx status code
func (o *PerformancePackageModeOfSalesDeleteNoContent) IsServerError() bool {
	return false
}

// IsCode returns true when this performance package mode of sales delete no content response a status code equal to that given
func (o *PerformancePackageModeOfSalesDeleteNoContent) IsCode(code int) bool {
	return code == 204
}

// Code gets the status code for the performance package mode of sales delete no content response
func (o *PerformancePackageModeOfSalesDeleteNoContent) Code() int {
	return 204
}

func (o *PerformancePackageModeOfSalesDeleteNoContent) Error() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePackageModeOfSales/{performancePackageModeOfSaleId}][%d] performancePackageModeOfSalesDeleteNoContent ", 204)
}

func (o *PerformancePackageModeOfSalesDeleteNoContent) String() string {
	return fmt.Sprintf("[DELETE /TXN/PerformancePackageModeOfSales/{performancePackageModeOfSaleId}][%d] performancePackageModeOfSalesDeleteNoContent ", 204)
}

func (o *PerformancePackageModeOfSalesDeleteNoContent) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}