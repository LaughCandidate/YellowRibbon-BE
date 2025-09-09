package laughcandidate.yellowribbonbe.product.service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.ProductErrorCode;
import laughcandidate.yellowribbonbe.product.constants.ProductConstants;
import laughcandidate.yellowribbonbe.product.dto.ProductDetailResponse;
import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.product.entity.*;
import laughcandidate.yellowribbonbe.product.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ProductService {

    private final ProductRepository productRepository;

    public List<ProductListResponse> getProducts(String category, Long badgeId) {
        ProductCategory productCategory = parseCategory(category);
        List<Product> products = productRepository.findFilteredProducts(productCategory, badgeId);
        
        return products.stream()
                .map(this::convertToResponse)
                .toList();
    }

    public ProductDetailResponse getProductDetail(Long productId) {
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new CustomException(ProductErrorCode.PRODUCT_NOT_FOUND));
        
        return convertToDetailResponse(product);
    }

    private ProductCategory parseCategory(String category) {
        if (category == null || category.trim().isEmpty()) {
            return null;
        }
        
        try {
            return ProductCategory.valueOf(category.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new CustomException(ProductErrorCode.INVALID_PRODUCT_CATEGORY, category);
        }
    }

    private ProductListResponse convertToResponse(Product product) {
        String badgeCategory = Optional.ofNullable(product.getBadge())
                .map(badge -> badge.getCategory())
                .map(category -> category.getCategory())
                .orElse(null);
        
        ProductListResponse.ProductListResponseBuilder builder = ProductListResponse.builder()
                .productId(product.getId())
                .badgeCategory(badgeCategory)
                .productName(product.getName())
                .description(product.getDescription())
                .category(product.getCategory().getDescription());

        if (product instanceof LoanProduct loan) {
            BigDecimal maxRate = loan.getInterestRate().add(ProductConstants.LOAN_ADDITIONAL_RATE);
            builder.interestRate(String.format("%.2f%% ~ %.2f%%", loan.getInterestRate(), maxRate))
                   .loanLimit("최대 " + (loan.getLoanLimit().longValue() / ProductConstants.WON_TO_HUNDRED_MILLION) + "억");
        } else if (product instanceof DepositProduct deposit) {
            BigDecimal maxRate = deposit.getInterestRate().add(ProductConstants.DEPOSIT_ADDITIONAL_RATE);
            builder.interestRate(String.format("%.2f%% ~ %.2f%%", deposit.getInterestRate(), maxRate))
                   .displayPeriod(ProductConstants.DEFAULT_PERIOD);
        } else if (product instanceof InstallmentSavingProduct saving) {
            BigDecimal maxRate = saving.getInterestRate().add(ProductConstants.SAVINGS_ADDITIONAL_RATE);
            builder.interestRate(String.format("%.2f%% ~ %.2f%%", saving.getInterestRate(), maxRate))
                   .displayPeriod(ProductConstants.DEFAULT_PERIOD);
        } else if (product instanceof InsuranceProduct insurance) {
            builder.coverageType(insurance.getCoverageType().getDescription());
        }

        return builder.build();
    }

    private ProductDetailResponse convertToDetailResponse(Product product) {
        ProductDetailResponse.ProductDetailResponseBuilder builder = ProductDetailResponse.builder()
                .productId(product.getId())
                .productName(product.getName())
                .description(product.getDescription())
                .category(product.getCategory().getDescription());

        if (product instanceof LoanProduct loan) {
            BigDecimal maxRate = loan.getInterestRate().add(ProductConstants.LOAN_ADDITIONAL_RATE);
            builder.minInterestRate(String.format("연 %.2f%%", loan.getInterestRate()))
                   .maxInterestRate(String.format("%.2f%%", maxRate))
                   .loanLimit((loan.getLoanLimit().longValue() / ProductConstants.WON_TO_HUNDRED_MILLION) + "억원");
        } else if (product instanceof DepositProduct deposit) {
            BigDecimal maxRate = deposit.getInterestRate().add(ProductConstants.DEPOSIT_ADDITIONAL_RATE);
            builder.minInterestRate(String.format("연 %.2f%%", deposit.getInterestRate()))
                   .maxInterestRate(String.format("%.2f%%", maxRate))
                   .minDeposit((deposit.getMinAmount().longValue() / ProductConstants.WON_TO_MILLION) + "만원");
        } else if (product instanceof InstallmentSavingProduct saving) {
            BigDecimal maxRate = saving.getInterestRate().add(ProductConstants.SAVINGS_ADDITIONAL_RATE);
            builder.minInterestRate(String.format("연 %.2f%%", saving.getInterestRate()))
                   .maxInterestRate(String.format("%.2f%%", maxRate))
                   .minSavingsAmount(String.format("월 %d만원", saving.getMinDepositAmount().longValue() / ProductConstants.WON_TO_MILLION))
                   .maxSavingsAmount(String.format("%d만원", saving.getMaxDepositAmount().longValue() / ProductConstants.WON_TO_MILLION));
        } else if (product instanceof InsuranceProduct insurance) {
            builder.monthlyPremium(String.format("%,d원부터", insurance.getPremium().longValue()))
                   .coveragePeriod(ProductConstants.INSURANCE_COVERAGE_PERIOD);
        }

        return builder.build();
    }
}
