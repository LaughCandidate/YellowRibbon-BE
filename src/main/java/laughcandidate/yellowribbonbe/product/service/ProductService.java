package laughcandidate.yellowribbonbe.product.service;

import laughcandidate.yellowribbonbe.product.dto.ProductListResponse;
import laughcandidate.yellowribbonbe.product.entity.*;
import laughcandidate.yellowribbonbe.product.repository.ProductRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ProductService {

    private final ProductRepository productRepository;

    public List<ProductListResponse> getProducts(String category) {
        ProductCategory productCategory = parseCategory(category);
        List<Product> products = productRepository.findFilteredProducts(productCategory);
        
        return products.stream()
                .map(this::convertToResponse)
                .collect(Collectors.toList());
    }

    private ProductCategory parseCategory(String category) {
        if (category == null || category.trim().isEmpty()) {
            return null;
        }
        
        try {
            return ProductCategory.valueOf(category.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("잘못된 카테고리입니다: " + category);
        }
    }

    private ProductListResponse convertToResponse(Product product) {
        String badgeCategory = null;
        if (product.getBadge() != null && product.getBadge().getCategory() != null) {
            badgeCategory = product.getBadge().getCategory().getCategory();
        }
        
        ProductListResponse.ProductListResponseBuilder builder = ProductListResponse.builder()
                .productId(product.getId())
                .badgeCategory(badgeCategory)
                .productName(product.getName())
                .description(product.getDescription())
                .category(product.getCategory().getDescription());

        if (product instanceof LoanProduct) {
            LoanProduct loan = (LoanProduct) product;
            // 대출: 기준금리 ~ 기준금리+2.31%
            BigDecimal maxRate = loan.getInterestRate().add(new BigDecimal("2.31"));
            builder.interestRate(String.format("%.2f ~ %.2f", loan.getInterestRate(), maxRate))
                   .loanLimit("최대 " + (loan.getLoanLimit().longValue() / 100000000) + "억");
        } else if (product instanceof DepositProduct) {
            DepositProduct deposit = (DepositProduct) product;
            // 예금: 기준금리 ~ 기준금리+1.20%
            BigDecimal maxRate = deposit.getInterestRate().add(new BigDecimal("1.20"));
            builder.interestRate(String.format("%.2f ~ %.2f", deposit.getInterestRate(), maxRate))
                   .displayPeriod("12개월 기준");
        } else if (product instanceof InstallmentSavingProduct) {
            InstallmentSavingProduct saving = (InstallmentSavingProduct) product;
            // 적금: 기준금리 ~ 기준금리+3.00%
            BigDecimal maxRate = saving.getInterestRate().add(new BigDecimal("3.00"));
            builder.interestRate(String.format("%.2f ~ %.2f", saving.getInterestRate(), maxRate))
                   .displayPeriod("12개월 기준");
        } else if (product instanceof InsuranceProduct) {
            InsuranceProduct insurance = (InsuranceProduct) product;
            builder.coverageType(insurance.getCoverageType().getDescription());
        }

        return builder.build();
    }
}
