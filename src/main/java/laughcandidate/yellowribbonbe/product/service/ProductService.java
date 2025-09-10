package laughcandidate.yellowribbonbe.product.service;

import laughcandidate.yellowribbonbe.global.exception.CustomException;
import laughcandidate.yellowribbonbe.global.exception.errorCode.ProductErrorCode;
import laughcandidate.yellowribbonbe.global.exception.errorCode.MyDataErrorCode;
import laughcandidate.yellowribbonbe.mydata.entity.*;
import laughcandidate.yellowribbonbe.mydata.repository.MyDataRepository;
import laughcandidate.yellowribbonbe.product.constants.ProductConstants;
import laughcandidate.yellowribbonbe.product.dto.*;
import laughcandidate.yellowribbonbe.product.entity.*;
import laughcandidate.yellowribbonbe.product.repository.ProductRepository;
import laughcandidate.yellowribbonbe.product.repository.UserBenefitProductRepository;
import laughcandidate.yellowribbonbe.product.util.FinancialCalculator;
import laughcandidate.yellowribbonbe.product.util.ScoreConverter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class ProductService {

    private final ProductRepository productRepository;
    private final UserBenefitProductRepository userBenefitProductRepository;
    private final MyDataRepository myDataRepository;
    private final FinancialCalculator financialCalculator;
    private final ScoreConverter scoreConverter;

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

    @Transactional(readOnly = true)
    public List<UserBenefitProductResponse> getMyBenefitProducts(Long userId) {
        List<UserBenefitProduct> userBenefitProducts = 
                userBenefitProductRepository.findActiveUserBenefitProductsByUserId(userId);
        
        return userBenefitProducts.stream()
                .map(UserBenefitProductResponse::from)
                .toList();
    }

    public ComparisonResponse compareProducts(Long productId, Long myDataId, Long userId) {
        // 1. 데이터 조회 및 검증
        Product benefitProduct = productRepository.findById(productId)
                .orElseThrow(() -> new CustomException(ProductErrorCode.PRODUCT_NOT_FOUND));
                
        MyData userData = myDataRepository.findByIdAndUserId(myDataId, userId)
                .orElseThrow(() -> new CustomException(MyDataErrorCode.MYDATA_NOT_FOUND));
        
        // 2. 카테고리 일치 검증
        if (benefitProduct.getCategory() != userData.getCategory()) {
            throw new CustomException(ProductErrorCode.CATEGORY_MISMATCH);
        }
        
        // 3. 입력값 검증
        validateUserData(userData);
        
        // 3. 카테고리별 비교 수행
        return switch (benefitProduct.getCategory()) {
            case LOAN -> compareLoanProducts((LoanProduct) benefitProduct, (MyDataLoan) userData);
            case DEPOSIT -> compareDepositProducts((DepositProduct) benefitProduct, (MyDataDeposit) userData);
            case SAVINGS -> compareSavingsProducts((InstallmentSavingProduct) benefitProduct, (MyDataSavings) userData);
            case INSURANCE -> compareInsuranceProducts((InsuranceProduct) benefitProduct, (MyDataInsurance) userData);
        };
    }

    private ComparisonResponse compareLoanProducts(LoanProduct benefitProduct, MyDataLoan userData) {
        // 1. 계산된 지표 준비
        CalculatedMetrics userMetrics = calculateLoanMetrics(userData);
        CalculatedMetrics benefitMetrics = calculateBenefitLoanMetrics(benefitProduct, userData);
        
        // 2. 그래프 데이터 생성 (0-100 점수)
        Map<String, GraphComparisonItem> graphData = createLoanGraphData(userMetrics, benefitMetrics);
        
        // 3. 표 데이터 생성 (실제 값)
        Map<String, TableComparisonItem> tableData = createLoanTableData(userMetrics, benefitMetrics);
        
        // 4. 주요 혜택 계산
        String mainBenefit = calculateLoanMainBenefit(userMetrics, benefitMetrics);
        
        return ComparisonResponse.builder()
                .category("대출")
                .graphData(graphData)
                .tableData(tableData)
                .userProduct(createUserProductSummary(userData))
                .benefitProduct(createBenefitProductSummary(benefitProduct, mainBenefit))
                .build();
    }

    private CalculatedMetrics calculateLoanMetrics(MyDataLoan loanData) {
        int remainingMonths = financialCalculator.calculateRemainingMonths(loanData.getMaturityDate());
        BigDecimal monthlyPayment = financialCalculator.calculateMonthlyPayment(
                loanData.getRemainPrincipal(), loanData.getInterestRate(), remainingMonths);
        BigDecimal totalInterest = financialCalculator.calculateTotalInterestBurden(
                monthlyPayment, remainingMonths, loanData.getRemainPrincipal());
        
        return CalculatedMetrics.builder()
                .interestRate(loanData.getInterestRate())
                .monthlyPayment(monthlyPayment)
                .totalInterestBurden(totalInterest)
                .prepaymentFee(loanData.getPrepaymentFeeRate())
                .loanLimit(loanData.getLoanLimit())
                .remainingMonths(remainingMonths)
                .build();
    }

    private CalculatedMetrics calculateBenefitLoanMetrics(LoanProduct benefitProduct, MyDataLoan userData) {
        // 혜택 상품에 없는 값들을 사용자 데이터 값으로 설정
        int remainingMonths = financialCalculator.calculateRemainingMonths(userData.getMaturityDate());
        BigDecimal loanAmount = userData.getRemainPrincipal();
        
        BigDecimal monthlyPayment = financialCalculator.calculateMonthlyPayment(
                loanAmount, benefitProduct.getInterestRate(), remainingMonths);
        BigDecimal totalInterest = financialCalculator.calculateTotalInterestBurden(
                monthlyPayment, remainingMonths, loanAmount);
        
        return CalculatedMetrics.builder()
                .interestRate(benefitProduct.getInterestRate())
                .monthlyPayment(monthlyPayment)
                .totalInterestBurden(totalInterest)
                .prepaymentFee(benefitProduct.getPrepaymentFeeRate())
                .loanLimit(benefitProduct.getLoanLimit())
                .remainingMonths(remainingMonths)
                .build();
    }

    private Map<String, GraphComparisonItem> createLoanGraphData(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        Map<String, GraphComparisonItem> graphData = new LinkedHashMap<>();

        graphData.put("금리", createGraphComparisonItem(
                userMetrics.getInterestRate(), benefitMetrics.getInterestRate(),
                ProductCategory.LOAN, "금리", true));

        graphData.put("최대한도", createGraphComparisonItem(
                userMetrics.getLoanLimit(), benefitMetrics.getLoanLimit(),
                ProductCategory.LOAN, "최대한도", false));

        graphData.put("중도상환수수료율", createGraphComparisonItem(
                userMetrics.getPrepaymentFee(), benefitMetrics.getPrepaymentFee(),
                ProductCategory.LOAN, "중도상환수수료율", true));

        graphData.put("월상환액", createGraphComparisonItem(
                userMetrics.getMonthlyPayment(), benefitMetrics.getMonthlyPayment(),
                ProductCategory.LOAN, "월상환액", false));

        graphData.put("총이자부담액", createGraphComparisonItem(
                userMetrics.getTotalInterestBurden(), benefitMetrics.getTotalInterestBurden(),
                ProductCategory.LOAN, "총이자부담액", false));
        
        return graphData;
    }

    private Map<String, TableComparisonItem> createLoanTableData(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        Map<String, TableComparisonItem> tableData = new LinkedHashMap<>();

        tableData.put("금리", createTableComparisonItem(
                userMetrics.getInterestRate(), benefitMetrics.getInterestRate(), true, "금리", ProductCategory.LOAN));

        tableData.put("월상환액", createTableComparisonItem(
                userMetrics.getMonthlyPayment(), benefitMetrics.getMonthlyPayment(), false, "월상환액", ProductCategory.LOAN));

        tableData.put("총이자부담액", createTableComparisonItem(
                userMetrics.getTotalInterestBurden(), benefitMetrics.getTotalInterestBurden(), false, "총이자부담액", ProductCategory.LOAN));

        tableData.put("중도상환수수료", createTableComparisonItem(
                userMetrics.getPrepaymentFee(), benefitMetrics.getPrepaymentFee(), true, "중도상환수수료", ProductCategory.LOAN));
        
        return tableData;
    }

    private String calculateLoanMainBenefit(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        BigDecimal interestSaved = userMetrics.getTotalInterestBurden().subtract(benefitMetrics.getTotalInterestBurden());
        
        if (interestSaved.compareTo(BigDecimal.ZERO) > 0) {
            return String.format("총 %,d원 이익", interestSaved.longValue());
        } else if (interestSaved.compareTo(BigDecimal.ZERO) < 0) {
            return String.format("총 %,d원 손실", Math.abs(interestSaved.longValue()));
        } else {
            return "동일한 조건";
        }
    }
    
    private String formatValue(BigDecimal value, boolean isPercentage) {
        if (value == null) return "-";

        if (isPercentage) {
            return String.format("연 %.2f%%", value);
        } else {
            // 금액 포맷팅 (천단위 콤마)
            if (value.compareTo(BigDecimal.valueOf(10000)) >= 0) {
                return String.format("%,d", value.longValue());
            } else {
                // 작은 수치는 점수로 표시 (우대조건 등)
                return String.format("%d점", value.intValue());
            }
        }
    }
    
    private String calculateDifference(BigDecimal userValue, BigDecimal benefitValue, boolean isPercentage) {
        if (userValue == null || benefitValue == null) return "-";

        BigDecimal diff = benefitValue.subtract(userValue);
        String sign = diff.compareTo(BigDecimal.ZERO) >= 0 ? "+" : "";

        if (isPercentage) {
            return String.format("%s%.2f%%p", sign, diff);
        } else {
            if (diff.abs().compareTo(BigDecimal.valueOf(10000)) >= 0) {
                return String.format("%s%,d", sign, diff.longValue());
            } else {
                return String.format("%s%d점", sign, diff.intValue());
            }
        }
    }

    private ProductSummary createUserProductSummary(MyData userData) {
        return ProductSummary.builder()
                .productName(userData.getProductName())
                .category(userData.getCategory().getDescription())
                .mainBenefit("현재 보유 상품")
                .build();
    }

    private ProductSummary createBenefitProductSummary(Product benefitProduct, String mainBenefit) {
        return ProductSummary.builder()
                .productName(benefitProduct.getName())
                .category(benefitProduct.getCategory().getDescription())
                .mainBenefit(mainBenefit)
                .build();
    }


    private ComparisonResponse compareDepositProducts(DepositProduct benefitProduct, MyDataDeposit userData) {
        // 1. 계산된 지표 준비
        CalculatedMetrics userMetrics = calculateDepositMetrics(userData);
        CalculatedMetrics benefitMetrics = calculateBenefitDepositMetrics(benefitProduct, userData);
        
        // 2. 그래프 데이터 생성 (0-100 점수)
        Map<String, GraphComparisonItem> graphData = createDepositGraphData(userMetrics, benefitMetrics);
        
        // 3. 표 데이터 생성 (실제 값)
        Map<String, TableComparisonItem> tableData = createDepositTableData(userMetrics, benefitMetrics);
        
        // 4. 주요 혜택 계산
        String mainBenefit = calculateDepositMainBenefit(userMetrics, benefitMetrics);
        
        return ComparisonResponse.builder()
                .category("예금")
                .graphData(graphData)
                .tableData(tableData)
                .userProduct(createUserProductSummary(userData))
                .benefitProduct(createBenefitProductSummary(benefitProduct, mainBenefit))
                .build();
    }

    private CalculatedMetrics calculateDepositMetrics(MyDataDeposit depositData) {
        int depositMonths = financialCalculator.calculateMonthsBetween(
                depositData.getStartDate(), depositData.getMaturityDate());
        BigDecimal maturityInterest = financialCalculator.calculateDepositInterest(
                depositData.getAmount(), depositData.getInterestRate(), depositMonths);
        BigDecimal maturityAmount = depositData.getAmount().add(maturityInterest);
        
        return CalculatedMetrics.builder()
                .interestRate(depositData.getInterestRate())
                .maturityInterest(maturityInterest)
                .maturityAmount(maturityAmount)
                .depositAmount(depositData.getAmount())
                .minAmount(depositData.getMinAmount())
                .terminationRate(depositData.getTerminationRate())
                .preferential(depositData.getPreferential())
                .depositMonths(depositMonths)
                .build();
    }

    private CalculatedMetrics calculateBenefitDepositMetrics(DepositProduct benefitProduct, MyDataDeposit userData) {
        // 혜택 상품에 없는 값들은 사용자 데이터 값으로 설정
        int depositMonths = financialCalculator.calculateMonthsBetween(
                userData.getStartDate(), userData.getMaturityDate());
        BigDecimal depositAmount = userData.getAmount(); // 사용자가 실제 예치한 금액
        
        BigDecimal maturityInterest = financialCalculator.calculateDepositInterest(
                depositAmount, benefitProduct.getInterestRate(), depositMonths);
        BigDecimal maturityAmount = depositAmount.add(maturityInterest);
        
        return CalculatedMetrics.builder()
                .interestRate(benefitProduct.getInterestRate())
                .maturityInterest(maturityInterest)
                .maturityAmount(maturityAmount)
                .depositAmount(depositAmount)
                .minAmount(benefitProduct.getMinAmount())
                .terminationRate(benefitProduct.getTerminationRate())
                .preferential(benefitProduct.getPreferentialScore() != null ? benefitProduct.getPreferentialScore() : 0)
                .depositMonths(depositMonths)
                .build();
    }

    private Map<String, GraphComparisonItem> createDepositGraphData(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        Map<String, GraphComparisonItem> graphData = new LinkedHashMap<>();

        graphData.put("금리", createGraphComparisonItem(
                userMetrics.getInterestRate(), benefitMetrics.getInterestRate(),
                ProductCategory.DEPOSIT, "금리", true));

        graphData.put("최소예치금", createGraphComparisonItem(
                userMetrics.getMinAmount(), benefitMetrics.getMinAmount(),
                ProductCategory.DEPOSIT, "최소예치금", false));

        graphData.put("중도해지이율", createGraphComparisonItem(
                userMetrics.getTerminationRate(), benefitMetrics.getTerminationRate(),
                ProductCategory.DEPOSIT, "중도해지이율", true));

        graphData.put("만기이자", createGraphComparisonItem(
                userMetrics.getMaturityInterest(), benefitMetrics.getMaturityInterest(),
                ProductCategory.DEPOSIT, "만기이자", false));
        
        // 우대조건 비교 (높을수록 좋음)
        graphData.put("우대조건", createGraphComparisonItem(
                userMetrics.getPreferential() != null ? BigDecimal.valueOf(userMetrics.getPreferential()) : BigDecimal.ZERO, 
                benefitMetrics.getPreferential() != null ? BigDecimal.valueOf(benefitMetrics.getPreferential()) : BigDecimal.ZERO,
                ProductCategory.DEPOSIT, "우대조건", false));
        
        return graphData;
    }

    private Map<String, TableComparisonItem> createDepositTableData(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        Map<String, TableComparisonItem> tableData = new LinkedHashMap<>();

        tableData.put("금리", createTableComparisonItem(
                userMetrics.getInterestRate(), benefitMetrics.getInterestRate(), true, "금리", ProductCategory.DEPOSIT));

        tableData.put("만기이자", createTableComparisonItem(
                userMetrics.getMaturityInterest(), benefitMetrics.getMaturityInterest(), false, "만기이자", ProductCategory.DEPOSIT));

        tableData.put("만기수령액", createTableComparisonItem(
                userMetrics.getMaturityAmount(), benefitMetrics.getMaturityAmount(), false, "만기수령액", ProductCategory.DEPOSIT));
        
        return tableData;
    }

    private String calculateDepositMainBenefit(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        BigDecimal interestDifference = benefitMetrics.getMaturityInterest().subtract(userMetrics.getMaturityInterest());
        
        if (interestDifference.compareTo(BigDecimal.ZERO) > 0) {
            return String.format("만기 시 %,d원 이익", interestDifference.longValue());
        } else if (interestDifference.compareTo(BigDecimal.ZERO) < 0) {
            return String.format("만기 시 %,d원 손실", Math.abs(interestDifference.longValue()));
        } else {
            return "동일한 조건";
        }
    }

    private ComparisonResponse compareSavingsProducts(InstallmentSavingProduct benefitProduct, MyDataSavings userData) {
        // 1. 계산된 지표 준비
        CalculatedMetrics userMetrics = calculateSavingsMetrics(userData);
        CalculatedMetrics benefitMetrics = calculateBenefitSavingsMetrics(benefitProduct, userData);
        
        // 2. 그래프 데이터 생성 (0-100 점수)
        Map<String, GraphComparisonItem> graphData = createSavingsGraphData(userMetrics, benefitMetrics);
        
        // 3. 표 데이터 생성 (실제 값)
        Map<String, TableComparisonItem> tableData = createSavingsTableData(userMetrics, benefitMetrics);
        
        // 4. 주요 혜택 계산
        String mainBenefit = calculateSavingsMainBenefit(userMetrics, benefitMetrics);
        
        return ComparisonResponse.builder()
                .category("적금")
                .graphData(graphData)
                .tableData(tableData)
                .userProduct(createUserProductSummary(userData))
                .benefitProduct(createBenefitProductSummary(benefitProduct, mainBenefit))
                .build();
    }

    private CalculatedMetrics calculateSavingsMetrics(MyDataSavings savingsData) {
        int savingsMonths = financialCalculator.calculateMonthsBetween(
                savingsData.getStartDate(), savingsData.getMaturityDate());
        BigDecimal totalDeposit = savingsData.getMonthlyPay().multiply(BigDecimal.valueOf(savingsMonths));
        BigDecimal savingsMaturityAmount = financialCalculator.calculateSavingsMaturity(
                savingsData.getMonthlyPay(), savingsData.getInterestRate(), savingsMonths);
        BigDecimal savingsMaturityInterest = savingsMaturityAmount.subtract(totalDeposit);
        
        return CalculatedMetrics.builder()
                .interestRate(savingsData.getInterestRate())
                .totalDeposit(totalDeposit)
                .savingsMaturityAmount(savingsMaturityAmount)
                .savingsMaturityInterest(savingsMaturityInterest)
                .monthlyAmount(savingsData.getMonthlyPay())
                .maxAmount(savingsData.getMaxAmount())
                .terminationRate(savingsData.getTerminationRate())
                .preferential(savingsData.getPreferential())
                .savingsMonths(savingsMonths)
                .build();
    }

    private CalculatedMetrics calculateBenefitSavingsMetrics(InstallmentSavingProduct benefitProduct, MyDataSavings userData) {
        // 혜택 상품에 없는 값들은 사용자 데이터 값으로 설정
        int savingsMonths = financialCalculator.calculateMonthsBetween(
                userData.getStartDate(), userData.getMaturityDate());
        BigDecimal monthlyAmount = userData.getMonthlyPay(); // 사용자 월납입액 그대로 사용
        
        BigDecimal totalDeposit = monthlyAmount.multiply(BigDecimal.valueOf(savingsMonths));
        BigDecimal savingsMaturityAmount = financialCalculator.calculateSavingsMaturity(
                monthlyAmount, benefitProduct.getInterestRate(), savingsMonths);
        BigDecimal savingsMaturityInterest = savingsMaturityAmount.subtract(totalDeposit);
        
        return CalculatedMetrics.builder()
                .interestRate(benefitProduct.getInterestRate())
                .totalDeposit(totalDeposit)
                .savingsMaturityAmount(savingsMaturityAmount)
                .savingsMaturityInterest(savingsMaturityInterest)
                .monthlyAmount(monthlyAmount)
                .maxAmount(benefitProduct.getMaxDepositAmount())
                .terminationRate(benefitProduct.getTerminationRate())
                .preferential(benefitProduct.getPreferentialScore() != null ? benefitProduct.getPreferentialScore() : 0)
                .savingsMonths(savingsMonths)
                .build();
    }

    private Map<String, GraphComparisonItem> createSavingsGraphData(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        Map<String, GraphComparisonItem> graphData = new LinkedHashMap<>();

        graphData.put("금리", createGraphComparisonItem(
                userMetrics.getInterestRate(), benefitMetrics.getInterestRate(),
                ProductCategory.SAVINGS, "금리", true));

        graphData.put("만기수령액", createGraphComparisonItem(
                userMetrics.getSavingsMaturityAmount(), benefitMetrics.getSavingsMaturityAmount(),
                ProductCategory.SAVINGS, "만기수령액", false));

        graphData.put("최대한도", createGraphComparisonItem(
                userMetrics.getMaxAmount(), benefitMetrics.getMaxAmount(),
                ProductCategory.SAVINGS, "최대한도", false));

        graphData.put("중도해지이율", createGraphComparisonItem(
                userMetrics.getTerminationRate(), benefitMetrics.getTerminationRate(),
                ProductCategory.SAVINGS, "중도해지이율", true));

        graphData.put("우대조건", createGraphComparisonItem(
                userMetrics.getPreferential() != null ? BigDecimal.valueOf(userMetrics.getPreferential()) : BigDecimal.ZERO, 
                benefitMetrics.getPreferential() != null ? BigDecimal.valueOf(benefitMetrics.getPreferential()) : BigDecimal.ZERO,
                ProductCategory.SAVINGS, "우대조건", false));
        
        return graphData;
    }

    private Map<String, TableComparisonItem> createSavingsTableData(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        Map<String, TableComparisonItem> tableData = new LinkedHashMap<>();

        tableData.put("금리", createTableComparisonItem(
                userMetrics.getInterestRate(), benefitMetrics.getInterestRate(), true, "금리", ProductCategory.SAVINGS));

        tableData.put("총납입액", createTableComparisonItem(
                userMetrics.getTotalDeposit(), benefitMetrics.getTotalDeposit(), false, "총납입액", ProductCategory.SAVINGS));

        tableData.put("만기이자", createTableComparisonItem(
                userMetrics.getSavingsMaturityInterest(), benefitMetrics.getSavingsMaturityInterest(), false, "만기이자", ProductCategory.SAVINGS));

        tableData.put("만기수령액", createTableComparisonItem(
                userMetrics.getSavingsMaturityAmount(), benefitMetrics.getSavingsMaturityAmount(), false, "만기수령액", ProductCategory.SAVINGS));
        
        return tableData;
    }

    private String calculateSavingsMainBenefit(CalculatedMetrics userMetrics, CalculatedMetrics benefitMetrics) {
        BigDecimal interestDifference = benefitMetrics.getSavingsMaturityInterest().subtract(userMetrics.getSavingsMaturityInterest());
        
        if (interestDifference.compareTo(BigDecimal.ZERO) > 0) {
            return String.format("만기 시 %,d원 이익", interestDifference.longValue());
        } else if (interestDifference.compareTo(BigDecimal.ZERO) < 0) {
            return String.format("만기 시 %,d원 손실", Math.abs(interestDifference.longValue()));
        } else {
            return "동일한 조건";
        }
    }

    private ComparisonResponse compareInsuranceProducts(InsuranceProduct benefitProduct, MyDataInsurance userData) {
        // 1. 그래프 데이터 생성 (0-100 점수)
        Map<String, GraphComparisonItem> graphData = createInsuranceGraphData(benefitProduct, userData);
        
        // 2. 표 데이터 생성 (실제 값)
        Map<String, TableComparisonItem> tableData = createInsuranceTableData(benefitProduct, userData);
        
        // 3. 주요 혜택 계산
        String mainBenefit = calculateInsuranceMainBenefit(benefitProduct, userData);
        
        return ComparisonResponse.builder()
                .category("보험")
                .graphData(graphData)
                .tableData(tableData)
                .userProduct(createUserProductSummary(userData))
                .benefitProduct(createBenefitProductSummary(benefitProduct, mainBenefit))
                .build();
    }

    private Map<String, GraphComparisonItem> createInsuranceGraphData(InsuranceProduct benefitProduct, MyDataInsurance userData) {
        Map<String, GraphComparisonItem> graphData = new LinkedHashMap<>();
        
        // 보험료 비교
        graphData.put("보험료", createGraphComparisonItem(
                userData.getPremium(), benefitProduct.getPremium(),
                ProductCategory.INSURANCE, "보험료", false));
        
        // 보장금액 비교
        graphData.put("보장금액", createGraphComparisonItem(
                userData.getCoverage(), benefitProduct.getCoverageAmount(),
                ProductCategory.INSURANCE, "보장금액", false));
        
        // 우대조건 비교
        graphData.put("우대조건", createGraphComparisonItem(
                userData.getPreferential() != null ? BigDecimal.valueOf(userData.getPreferential()) : BigDecimal.ZERO,
                benefitProduct.getPreferentialScore() != null ? BigDecimal.valueOf(benefitProduct.getPreferentialScore()) : BigDecimal.ZERO,
                ProductCategory.INSURANCE, "우대조건", false));
        
        return graphData;
    }

    private Map<String, TableComparisonItem> createInsuranceTableData(InsuranceProduct benefitProduct, MyDataInsurance userData) {
        Map<String, TableComparisonItem> tableData = new LinkedHashMap<>();

        tableData.put("보험료", createTableComparisonItem(
                userData.getPremium(), benefitProduct.getPremium(), false, "보험료", ProductCategory.INSURANCE));

        tableData.put("보장금액", createTableComparisonItem(
                userData.getCoverage(), benefitProduct.getCoverageAmount(), false, "보장금액", ProductCategory.INSURANCE));
        
        return tableData;
    }

    private String calculateInsuranceMainBenefit(InsuranceProduct benefitProduct, MyDataInsurance userData) {
        BigDecimal premiumDifference = userData.getPremium().subtract(benefitProduct.getPremium());
        BigDecimal coverageDifference = benefitProduct.getCoverageAmount().subtract(userData.getCoverage());
        
        // 혜택상품이 더 좋은 경우들
        if (premiumDifference.compareTo(BigDecimal.ZERO) > 0 && coverageDifference.compareTo(BigDecimal.ZERO) > 0) {
            return String.format("월 %,d원 절약, 보장 %,d원 증가", premiumDifference.longValue(), coverageDifference.longValue());
        } else if (premiumDifference.compareTo(BigDecimal.ZERO) > 0) {
            return String.format("월 %,d원 절약", premiumDifference.longValue());
        } else if (coverageDifference.compareTo(BigDecimal.ZERO) > 0) {
            return String.format("보장 %,d원 증가", coverageDifference.longValue());
        }
        
        // 사용자 상품이 더 좋은 경우들
        else if (premiumDifference.compareTo(BigDecimal.ZERO) < 0 && coverageDifference.compareTo(BigDecimal.ZERO) < 0) {
            return String.format("월 %,d원 손실, 보장 %,d원 감소", 
                    Math.abs(premiumDifference.longValue()), Math.abs(coverageDifference.longValue()));
        } else if (premiumDifference.compareTo(BigDecimal.ZERO) < 0) {
            return String.format("월 %,d원 손실", Math.abs(premiumDifference.longValue()));
        } else if (coverageDifference.compareTo(BigDecimal.ZERO) < 0) {
            return String.format("보장 %,d원 감소", Math.abs(coverageDifference.longValue()));
        }

        else {
            return "유사한 조건";
        }
    }


    private void validateUserData(MyData userData) {
        switch (userData.getCategory()) {
            case LOAN -> validateLoanData((MyDataLoan) userData);
            case DEPOSIT -> validateDepositData((MyDataDeposit) userData);
            case SAVINGS -> validateSavingsData((MyDataSavings) userData);
            case INSURANCE -> validateInsuranceData((MyDataInsurance) userData);
        }
    }
    

    private void validateLoanData(MyDataLoan loanData) {
        // 필수 데이터 존재 검증
        if (loanData.getRemainPrincipal() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "대출잔액");
        }
        if (loanData.getInterestRate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "금리");
        }
        if (loanData.getMaturityDate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "만기일자");
        }
        
        // 금액 검증
        if (loanData.getRemainPrincipal().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "대출잔액");
        }
        if (loanData.getLoanLimit() != null && loanData.getLoanLimit().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "대출한도");
        }
        
        // 금리 검증
        if (loanData.getInterestRate().compareTo(BigDecimal.ZERO) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_INTEREST_RATE);
        }
        if (loanData.getPrepaymentFeeRate() != null && loanData.getPrepaymentFeeRate().compareTo(BigDecimal.ZERO) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_INTEREST_RATE);
        }
        
        // 날짜 검증
        LocalDate today = LocalDate.now();
        if (loanData.getMaturityDate().isBefore(today)) {
            throw new CustomException(ProductErrorCode.INVALID_DATE_RANGE);
        }
        if (loanData.getExecDate() != null && loanData.getExecDate().isAfter(loanData.getMaturityDate())) {
            throw new CustomException(ProductErrorCode.INVALID_DATE_ORDER);
        }
        
        // 대출잔액이 원금보다 큰 경우 검증
        if (loanData.getPrincipal() != null && 
            loanData.getRemainPrincipal().compareTo(loanData.getPrincipal()) > 0) {
            throw new CustomException(ProductErrorCode.INVALID_CALCULATION_DATA, "대출잔액이 원금보다 클 수 없습니다");
        }
    }
    

    private void validateDepositData(MyDataDeposit depositData) {
        // 필수 데이터 존재 검증
        if (depositData.getAmount() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "예치금액");
        }
        if (depositData.getInterestRate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "금리");
        }
        if (depositData.getStartDate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "가입일자");
        }
        if (depositData.getMaturityDate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "만기일자");
        }
        
        // 금액 검증
        if (depositData.getAmount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "예치금액");
        }
        if (depositData.getMinAmount() != null && depositData.getMinAmount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "최소예치금");
        }
        
        // 금리 검증
        if (depositData.getInterestRate().compareTo(BigDecimal.ZERO) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_INTEREST_RATE);
        }
        if (depositData.getTerminationRate() != null && depositData.getTerminationRate().compareTo(BigDecimal.ZERO) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_INTEREST_RATE);
        }
        
        // 날짜 검증
        if (depositData.getStartDate().isAfter(depositData.getMaturityDate())) {
            throw new CustomException(ProductErrorCode.INVALID_DATE_ORDER);
        }
        
        // 최소예치금액 검증
        if (depositData.getMinAmount() != null && 
            depositData.getAmount().compareTo(depositData.getMinAmount()) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_CALCULATION_DATA, "예치금액이 최소예치금액보다 작습니다");
        }
    }
    

    private void validateSavingsData(MyDataSavings savingsData) {
        // 필수 데이터 존재 검증
        if (savingsData.getMonthlyPay() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "월납입액");
        }
        if (savingsData.getInterestRate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "금리");
        }
        if (savingsData.getStartDate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "가입일자");
        }
        if (savingsData.getMaturityDate() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "만기일자");
        }
        
        // 금액 검증
        if (savingsData.getMonthlyPay().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "월납입액");
        }
        if (savingsData.getMaxAmount() != null && savingsData.getMaxAmount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "최대한도");
        }
        
        // 금리 검증
        if (savingsData.getInterestRate().compareTo(BigDecimal.ZERO) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_INTEREST_RATE);
        }
        if (savingsData.getTerminationRate() != null && savingsData.getTerminationRate().compareTo(BigDecimal.ZERO) < 0) {
            throw new CustomException(ProductErrorCode.INVALID_INTEREST_RATE);
        }
        
        // 날짜 검증
        if (savingsData.getStartDate().isAfter(savingsData.getMaturityDate())) {
            throw new CustomException(ProductErrorCode.INVALID_DATE_ORDER);
        }
    }
    

    private void validateInsuranceData(MyDataInsurance insuranceData) {
        // 필수 데이터 존재 검증
        if (insuranceData.getPremium() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "보험료");
        }
        if (insuranceData.getCoverage() == null) {
            throw new CustomException(ProductErrorCode.MISSING_REQUIRED_DATA, "보장금액");
        }
        
        // 금액 검증
        if (insuranceData.getPremium().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "보험료");
        }
        if (insuranceData.getCoverage().compareTo(BigDecimal.ZERO) <= 0) {
            throw new CustomException(ProductErrorCode.ZERO_OR_NEGATIVE_AMOUNT, "보장금액");
        }
    }


    private GraphComparisonItem createGraphComparisonItem(BigDecimal userValue, BigDecimal benefitValue, 
                                                         ProductCategory category, String indicator, boolean isPercentage) {
        
        // null 값 처리
        if (userValue == null) userValue = BigDecimal.ZERO;
        if (benefitValue == null) benefitValue = BigDecimal.ZERO;
        
        int userScore = scoreConverter.convertToScore(category, indicator, userValue, benefitValue);
        int benefitScore = scoreConverter.convertToScore(category, indicator, benefitValue, userValue);
        
        String userFormatted = formatValue(userValue, isPercentage);
        String benefitFormatted = formatValue(benefitValue, isPercentage);
        String difference = calculateDifference(userValue, benefitValue, isPercentage);
        
        return GraphComparisonItem.builder()
                .userValue(userFormatted)
                .benefitValue(benefitFormatted)
                .difference(difference)
                .userScore(userScore)
                .benefitScore(benefitScore)
                .isBetter(benefitScore > userScore)
                .build();
    }


    private TableComparisonItem createTableComparisonItem(BigDecimal userValue, BigDecimal benefitValue, 
                                                         boolean isPercentage, String indicator, ProductCategory category) {
        
        // null 값 처리
        if (userValue == null) userValue = BigDecimal.ZERO;
        if (benefitValue == null) benefitValue = BigDecimal.ZERO;
        
        String userFormatted = formatValue(userValue, isPercentage);
        String benefitFormatted = formatValue(benefitValue, isPercentage);
        String difference = calculateDifference(userValue, benefitValue, isPercentage);
        
        // 항목별 비교 로직 (낮을수록 좋은 것 vs 높을수록 좋은 것)
        boolean isBetter = isIndicatorBetterWhenLower(indicator, category) 
            ? benefitValue.compareTo(userValue) < 0  // 낮을수록 좋음
            : benefitValue.compareTo(userValue) > 0; // 높을수록 좋음
        
        return TableComparisonItem.builder()
                .userValue(userFormatted)
                .benefitValue(benefitFormatted)
                .difference(difference)
                .isBetter(isBetter)
                .build();
    }
    

    private boolean isIndicatorBetterWhenLower(String indicator, ProductCategory category) {
        return switch (indicator) {
            case "금리" -> category == ProductCategory.LOAN; // 대출만 낮을수록 좋음, 예금/적금은 높을수록 좋음
            case "중도상환수수료", "중도상환수수료율", "월상환액", "총이자부담액", "보험료", "최소예치금" -> true;
            case "만기이자", "만기수령액", "보장금액", "최대한도", "중도해지이율", "우대조건", "총납입액" -> false;
            default -> false; // 기본값: 높을수록 좋음
        };
    }
}
