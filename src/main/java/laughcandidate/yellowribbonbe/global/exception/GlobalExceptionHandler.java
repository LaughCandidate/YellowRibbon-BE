package laughcandidate.yellowribbonbe.global.exception;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.AuthErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.CommonErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.ErrorCode;
import laughcandidate.yellowribbonbe.global.response.ErrorResponse;

@RestControllerAdvice
public class GlobalExceptionHandler {

	/**
	 * 커스텀 예외
	 */
	@ExceptionHandler(value = CustomException.class)
	public ResponseEntity<ErrorResponse<Void>> handleCustomException(CustomException e) {
		ErrorCode errorCode = e.getErrorCode();
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), e.getMessage()));
	}

	/**
	 * 데이터 유효성 검사가 실패할 경우
	 */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	protected ResponseEntity<ErrorResponse<Void>> handleMethodArgumentNotValidException(
		MethodArgumentNotValidException e) {

		BindingResult bindingResult = e.getBindingResult();
		String firstErrorMessage = null;

		if (!bindingResult.getFieldErrors().isEmpty()) {
			firstErrorMessage = bindingResult.getFieldErrors().get(0).getDefaultMessage();
		}
		else if (!bindingResult.getGlobalErrors().isEmpty()) {
			firstErrorMessage = bindingResult.getGlobalErrors().get(0).getDefaultMessage();
		}

		CommonErrorCode errorCode = CommonErrorCode.INVALID_VALUE;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), firstErrorMessage != null ? firstErrorMessage : errorCode.getMessage()));
	}

	/**
	 * 인증 예외
	 */
	@ExceptionHandler(AuthenticationException.class)
	public ResponseEntity<ErrorResponse<Void>> handleAuthenticationException(AuthenticationException e) {

		AuthErrorCode errorCode = AuthErrorCode.INVALID_TOKEN;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), errorCode.getMessage()));
	}

	/**
	 * 🆕 @ModelAttribute + @Valid 검증 실패 시 발생 (Form/Multipart 요청)
	 */
	@ExceptionHandler(ConstraintViolationException.class)
	public ResponseEntity<ErrorResponse<Void>> handleConstraintViolationException(
		ConstraintViolationException e) {

		String firstErrorMessage = null;

		for (ConstraintViolation<?> violation : e.getConstraintViolations()) {
			if (firstErrorMessage == null) {
				firstErrorMessage = violation.getMessage();
			}
		}

		CommonErrorCode errorCode = CommonErrorCode.INVALID_VALUE;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), firstErrorMessage != null ? firstErrorMessage : errorCode.getMessage()));
	}

	/**
	 * 인가 예외
	 */
	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ErrorResponse<Void>> handleAccessDeniedException(AccessDeniedException e) {

		AuthErrorCode errorCode = AuthErrorCode.ACCESS_DENIED;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), errorCode.getMessage()));
	}

	/**
	 * IllegalArgumentException 처리
	 */
	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<ErrorResponse<Void>> handleIllegalArgumentException(IllegalArgumentException e) {

		CommonErrorCode errorCode = CommonErrorCode.INVALID_ARGUMENT;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), errorCode.getMessage()));
	}

	/**
	 * RuntimeException 처리
	 */
	@ExceptionHandler(RuntimeException.class)
	public ResponseEntity<ErrorResponse<Void>> handleRuntimeException(RuntimeException e) {

		CommonErrorCode errorCode = CommonErrorCode.RUNTIME_ERROR;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), errorCode.getMessage()));
	}

	/**
	 * 일반적인 예외 처리 (catch-all)
	 */
	@ExceptionHandler(Exception.class)
	public ResponseEntity<ErrorResponse<Void>> handleGeneralException(Exception e) {

		CommonErrorCode errorCode = CommonErrorCode.INTERNAL_SERVER_ERROR;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), errorCode.getMessage()));
	}

	/**
	 * 필수 요청 파라미터 누락 예외
	 */
	@ExceptionHandler(MissingServletRequestParameterException.class)
	public ResponseEntity<ErrorResponse<Void>> handleMissingServletRequestParameterException(
		MissingServletRequestParameterException e) {

		CommonErrorCode errorCode = CommonErrorCode.MISSING_PARAMETER;
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ErrorResponse.error(errorCode.getCode(), errorCode.getMessage()));
	}

}