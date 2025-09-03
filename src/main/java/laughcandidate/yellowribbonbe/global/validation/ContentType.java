package laughcandidate.yellowribbonbe.global.validation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Documented
@Constraint(validatedBy = ContentTypeValidator.class)
@Target({ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
public @interface ContentType {
    String message() default "허용되지 않는 파일 타입입니다.";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    
    String[] allowed();
}