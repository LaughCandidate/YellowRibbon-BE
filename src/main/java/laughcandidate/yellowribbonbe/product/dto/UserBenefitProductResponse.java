package laughcandidate.yellowribbonbe.product.dto;

import laughcandidate.yellowribbonbe.product.entity.UserBenefitProduct;

import java.time.LocalDateTime;

public record UserBenefitProductResponse(
        Long productId,
        String productName,
        String description,
        String category,
        LocalDateTime subscribedAt
) {
    public static UserBenefitProductResponse from(UserBenefitProduct userBenefitProduct) {
        return new UserBenefitProductResponse(
                userBenefitProduct.getProduct().getId(),
                userBenefitProduct.getProduct().getName(),
                userBenefitProduct.getProduct().getDescription(),
                userBenefitProduct.getProduct().getCategory().getDescription(),
                userBenefitProduct.getCreatedAt()
        );
    }
}
