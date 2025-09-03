package laughcandidate.yellowribbonbe.global.validation;

import java.util.Arrays;
import java.util.List;

import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class ContentTypeValidator implements ConstraintValidator<ContentType, MultipartFile> {

    private List<String> allowedContentTypes;

    @Override
    public void initialize(ContentType constraintAnnotation) {
        this.allowedContentTypes = Arrays.asList(constraintAnnotation.allowed());
    }

    @Override
    public boolean isValid(MultipartFile file, ConstraintValidatorContext context) {
        if (file == null || file.isEmpty()) {
            return true;
        }
        
        String contentType = file.getContentType();
        return contentType != null && allowedContentTypes.contains(contentType);
    }
}