const { HTTP_STATUS } = require('../config/constants');

/**
 * Standard response handler
 */
class ResponseHandler {
  /**
   * Success response
   */
  static success(res, data = null, message = 'Success', statusCode = HTTP_STATUS.OK) {
    const response = {
      success: true,
      message,
      timestamp: new Date().toISOString()
    };

    if (data !== null) {
      response.data = data;
    }

    return res.status(statusCode).json(response);
  }

  /**
   * Success response with pagination
   */
  static paginated(res, data, pagination, message = 'Success') {
    const response = {
      success: true,
      message,
      timestamp: new Date().toISOString(),
      data: {
        items: data,
        pagination: {
          page: pagination.page,
          limit: pagination.limit,
          total: pagination.total,
          pages: Math.ceil(pagination.total / pagination.limit)
        }
      }
    };

    return res.status(HTTP_STATUS.OK).json(response);
  }

  /**
   * Created response
   */
  static created(res, data = null, message = 'Resource created successfully') {
    return this.success(res, data, message, HTTP_STATUS.CREATED);
  }

  /**
   * No content response
   */
  static noContent(res) {
    return res.status(HTTP_STATUS.NO_CONTENT).json();
  }

  /**
   * Error response
   */
  static error(res, message = 'An error occurred', statusCode = HTTP_STATUS.INTERNAL_SERVER_ERROR, errorCode = 'INTERNAL_ERROR', errors = null) {
    const response = {
      success: false,
      message,
      errorCode,
      timestamp: new Date().toISOString()
    };

    if (errors) {
      response.errors = errors;
    }

    return res.status(statusCode).json(response);
  }

  /**
   * Bad request response
   */
  static badRequest(res, message = 'Bad request', errors = null) {
    return this.error(res, message, HTTP_STATUS.BAD_REQUEST, 'BAD_REQUEST', errors);
  }

  /**
   * Unauthorized response
   */
  static unauthorized(res, message = 'Unauthorized') {
    return this.error(res, message, HTTP_STATUS.UNAUTHORIZED, 'UNAUTHORIZED');
  }

  /**
   * Forbidden response
   */
  static forbidden(res, message = 'Forbidden') {
    return this.error(res, message, HTTP_STATUS.FORBIDDEN, 'FORBIDDEN');
  }

  /**
   * Not found response
   */
  static notFound(res, message = 'Resource not found') {
    return this.error(res, message, HTTP_STATUS.NOT_FOUND, 'NOT_FOUND');
  }

  /**
   * Conflict response
   */
  static conflict(res, message = 'Resource already exists') {
    return this.error(res, message, HTTP_STATUS.CONFLICT, 'CONFLICT');
  }

  /**
   * Unprocessable entity response
   */
  static unprocessableEntity(res, message = 'Unprocessable entity', errors = null) {
    return this.error(res, message, HTTP_STATUS.UNPROCESSABLE_ENTITY, 'UNPROCESSABLE_ENTITY', errors);
  }
}

module.exports = ResponseHandler;