package laughcandidate.yellowribbonbe.global.validation;

import org.springframework.web.multipart.MultipartFile;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class FileSizeValidator implements ConstraintValidator<FileSize, MultipartFile> {

    private long maxSizeInBytes;

    @Override
    public void initialize(FileSize constraintAnnotation) {
        String maxSize = constraintAnnotation.max();
        this.maxSizeInBytes = parseSize(maxSize);
    }

    @Override
    public boolean isValid(MultipartFile file, ConstraintValidatorContext context) {
        if (file == null || file.isEmpty()) {
            return true;
        }
        
        return file.getSize() <= maxSizeInBytes;
    }

    private long parseSize(String size) {
        if (size == null || size.trim().isEmpty()) {
            return 10 * 1024 * 1024;
        }
        
        size = size.trim().toUpperCase();
        
        try {
            if (size.endsWith("KB")) {
                return Long.parseLong(size.substring(0, size.length() - 2)) * 1024L;
            } else if (size.endsWith("MB")) {
                return Long.parseLong(size.substring(0, size.length() - 2)) * 1024L * 1024L;
            } else if (size.endsWith("GB")) {
                return Long.parseLong(size.substring(0, size.length() - 2)) * 1024L * 1024L * 1024L;
            } else {
                return Long.parseLong(size);
            }
        } catch (NumberFormatException e) {
            return 10 * 1024 * 1024;
        }
    }
}